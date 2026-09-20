"""Model router: providers, role fallback chains, disk cache, budget-aware retries.

Provider wraps one entry from models.yaml's `providers:` section: an AsyncOpenAI
client, a concurrency semaphore, and an RPM throttle. Router wraps `roles:`: for
each role it walks the ordered fallback list, using the first enabled provider
that returns a usable reply, with a disk cache in front of every call.
"""

import asyncio
import hashlib
import json
import os
import re
import time
from pathlib import Path

import yaml
from openai import AsyncOpenAI

_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL)
_FENCE_RE = re.compile(r"```(?:json)?", re.IGNORECASE)

TERMINAL_STATUS_CODES = {400, 401, 403, 404}
OUT_OF_CREDITS_STATUS = 402


class OutOfCredits(Exception):
    """HTTP 402 from a provider: the account cannot pay for the call.

    Deliberately NOT a graceful degradation. Every other failure falls back to the next
    target so a scan survives; falling back here silently swaps the paid judge/scorer for a
    free model mid-run and produces a run whose numbers are not what they claim to be. This
    propagates through the agents' catch-alls and aborts the whole chain.
    """

# Reasoning models burn the completion budget on hidden thinking before emitting any
# content, so these are large. Override per role via models.yaml's top-level `max_tokens:`
# map, or per target with a `max_tokens:` key on the target itself.
DEFAULT_MAX_TOKENS = {
    "mapper": 8000,
    "hunter": 20000,
    "judge": 24000,
    "judge2": 24000,
    "poc": 8000,
    "scorer": 24000,
}
FALLBACK_MAX_TOKENS = 2048

# Roles whose cache key ignores the model id: any prior reply to the same prompt is replayed no
# matter which provider produced it. For the free hunt-side roles that keeps a rerun's candidate
# set stable (a fallback-served reply used to be cached under the fallback's id, so the next run
# tried the primary first, missed, and re-sampled). judge/scorer stay model-specific: a verdict
# depends on who gave it.
DEFAULT_CACHE_ANY_MODEL = ("mapper", "hunter", "poc")


def parse_cache_any_model(value) -> frozenset:
    """CLI value -> role set. None -> defaults; "" or "none" -> no roles; "a,b" -> those roles."""
    if value is None:
        return frozenset(DEFAULT_CACHE_ANY_MODEL)
    value = value.strip()
    if value.lower() in ("", "none"):
        return frozenset()
    return frozenset(r.strip() for r in value.split(",") if r.strip())
TRUNCATION_RATIO = 0.95


def strip_think(text: str) -> str:
    """Remove <think>...</think> blocks some reasoning models prepend."""
    return _THINK_RE.sub("", text).strip()


def extract_json(text: str):
    """Best-effort JSON extraction: strip think tags and code fences, then take
    the first '{' to the last '}'. Returns None (never raises) on failure."""
    text = strip_think(text)
    text = _FENCE_RE.sub("", text)
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1 or end < start:
        return None
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None


def cache_key(model: str, system: str, user: str, temperature: float, seed, salt: str = "") -> str:
    # `salt` (e.g. a hash of the cited files) only enters the key when given, so calls that
    # don't use one keep their existing keys.
    parts = [model, system, user, temperature, seed]
    if salt:
        parts.append(salt)
    payload = json.dumps(parts, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


class Provider:
    """One models.yaml provider: an OpenAI-compatible client plus rate limiting."""

    def __init__(self, name: str, cfg: dict, budget=None):
        self.name = name
        self.cfg = cfg
        self.budget = budget
        self.enabled = self._compute_enabled()

        self.client = None
        if self.enabled:
            key_env = cfg.get("key_env")
            api_key = os.environ.get(key_env, "") if key_env else ""
            # TODO(step 10): pass an x402 http_client here, built by hound.budget.x402_http.
            self.client = AsyncOpenAI(
                base_url=cfg["base_url"],
                api_key=api_key or "not-needed",
                timeout=cfg.get("timeout", 60),
                max_retries=0,
                http_client=None,
            )

        # Created lazily on first use (inside a running loop), not here: Router is
        # built synchronously by the CLI before any event loop exists.
        self._semaphore = None
        self._rpm_lock = None
        self._next_allowed = 0.0

    def _ensure_sync_primitives(self):
        if self._semaphore is None:
            self._semaphore = asyncio.Semaphore(self.cfg.get("concurrency", 1))
        if self._rpm_lock is None:
            self._rpm_lock = asyncio.Lock()

    def _compute_enabled(self) -> bool:
        if self.cfg.get("type") == "x402":
            wallet_present = bool(
                os.environ.get("X402_SVM_KEY") or os.environ.get("X402_EVM_KEY")
            )
            # Stub until step 10: with no Budget wired in, x402 providers stay off.
            return wallet_present and self.budget is not None
        key_env = self.cfg.get("key_env")
        if not key_env:
            return True
        return bool(os.environ.get(key_env))

    async def _throttle(self):
        self._ensure_sync_primitives()
        rpm = self.cfg.get("rpm")
        if not rpm:
            return
        interval = 60.0 / rpm
        async with self._rpm_lock:
            now = time.monotonic()
            wait = self._next_allowed - now
            self._next_allowed = max(now, self._next_allowed) + interval
        if wait > 0:
            await asyncio.sleep(wait)

    async def complete(self, *, model, messages, temperature, max_tokens, extra=None):
        self._ensure_sync_primitives()
        async with self._semaphore:
            await self._throttle()
            kwargs = dict(model=model, messages=messages, max_tokens=max_tokens)
            kwargs.update(extra or {})
            if temperature is not None:
                kwargs["temperature"] = temperature
            return await self.client.chat.completions.create(**kwargs)


class Router:
    """Dispatches role-based chat calls across models.yaml's provider fallback chains."""

    def __init__(
        self,
        models_path: str = "models.yaml",
        local_only: bool = False,
        seed: int = 0,
        fresh: bool = False,
        budget=None,
        cache_any_model=DEFAULT_CACHE_ANY_MODEL,
    ):
        config = yaml.safe_load(Path(models_path).read_text())
        self.cache_any_model = frozenset(cache_any_model)
        self.local_only = local_only
        self.seed = seed
        self.fresh = fresh
        self.budget = budget

        self.roles = config["roles"]
        self.role_max_tokens = {**DEFAULT_MAX_TOKENS, **(config.get("max_tokens") or {})}
        self.prices = {k: tuple(v) for k, v in (config.get("prices") or {}).items()}
        self.providers = {
            name: Provider(name, cfg, budget)
            for name, cfg in config["providers"].items()
        }

        if local_only and not any(p.cfg.get("local") for p in self.providers.values()):
            raise RuntimeError(
                "no local provider configured; local mode was removed after measuring "
                "0.09 tok/s on this machine."
            )

        self.cache_dir = Path(".hound_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.usage: dict[str, dict[str, int]] = {}
        self.call_log: list[dict] = []

    def targets(self, role: str):
        """Enabled providers for `role`, in fallback order."""
        if role not in self.roles:
            raise RuntimeError(f"unknown role {role!r} (not in models.yaml roles:)")

        result = []
        for target in self.roles[role]:
            provider = self.providers[target["provider"]]
            if not provider.enabled:
                continue
            if self.local_only and not provider.cfg.get("local"):
                continue
            if provider.cfg.get("type") == "x402":
                if self.budget is None or not self.budget.usable():
                    continue
            result.append((target, provider))

        if not result:
            raise RuntimeError(
                f"no enabled targets for role {role!r}: every provider is disabled, "
                f"filtered out by --local-only, or budget-exhausted"
            )
        return result

    def has(self, role: str) -> bool:
        try:
            self.targets(role)
            return True
        except RuntimeError:
            return False

    def _cached_reply_is_usable(self, role: str, key_model: str, meta_path: Path) -> tuple:
        """(usable, why_not). Only model-agnostic keys need checking (a model-specific key names
        its own model). A reply is replayed only if the model that ANSWERED it is a target
        currently configured for this role; otherwise a reply from a model since removed
        (say openrouter/free) would be pinned forever. An entry with no recorded model can't
        be verified, so it is not replayed."""
        if key_model != "*":
            return True, ""
        try:
            answered_by = json.loads(meta_path.read_text()).get("model")
        except (OSError, json.JSONDecodeError):
            return False, "no recorded answering model"
        configured = {t["model"] for t in self.roles.get(role, [])}
        if answered_by in configured:
            return True, ""
        return False, f"answered by {answered_by!r}, not a configured target for role {role!r}"

    def _resolve_max_tokens(self, role: str, target: dict, explicit) -> int:
        """explicit argument > the target's own max_tokens > role map > default."""
        if explicit is not None:
            return explicit
        if target.get("max_tokens"):
            return target["max_tokens"]
        return self.role_max_tokens.get(role, FALLBACK_MAX_TOKENS)

    def _record_usage(self, model: str, response):
        stats = self.usage.setdefault(
            model, {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0}
        )
        stats["calls"] += 1
        usage = getattr(response, "usage", None)
        if usage is not None:
            stats["prompt_tokens"] += getattr(usage, "prompt_tokens", 0) or 0
            stats["completion_tokens"] += getattr(usage, "completion_tokens", 0) or 0

    async def _call_with_retries(self, provider, model, messages, temperature, max_tokens, extra, role=""):
        cur_temperature = temperature
        retried_without_temperature = False
        last_error = None
        started = time.monotonic()

        for attempt in range(3):
            try:
                response = await provider.complete(
                    model=model,
                    messages=messages,
                    temperature=cur_temperature,
                    max_tokens=max_tokens,
                    extra=extra,
                )
            except Exception as exc:  # noqa: BLE001 - openai raises many subtypes
                status = getattr(exc, "status_code", None)
                message = str(exc)
                last_error = exc

                if status == OUT_OF_CREDITS_STATUS:
                    raise OutOfCredits(
                        f"{provider.name}/{model} for role {role!r}: {message[:200]}"
                    ) from exc

                # Reasoning models (e.g. gpt-5.6-luna) can reject a custom temperature.
                if (
                    status == 400
                    and "temperature" in message.lower()
                    and cur_temperature is not None
                    and not retried_without_temperature
                ):
                    cur_temperature = None
                    retried_without_temperature = True
                    continue

                if status == 404:
                    print(
                        f"[llm] MODEL NOT FOUND: {provider.name}/{model}, "
                        f"check the model id in models.yaml"
                    )

                if status in TERMINAL_STATUS_CODES or "budget" in message.lower():
                    break

                if attempt < 2:
                    delay = min(60, 4 * 2**attempt)
                    print(
                        f"[llm] BACKOFF {provider.name}/{model}: status={status} "
                        f"retry {attempt + 1}/2 in {delay}s"
                    )
                    await asyncio.sleep(delay)
                    continue
                break
            else:
                self._record_usage(model, response)
                content = response.choices[0].message.content or ""
                usage = getattr(response, "usage", None)
                completion_tokens = getattr(usage, "completion_tokens", 0) or 0
                finish_reason = getattr(response.choices[0], "finish_reason", None)
                meta = {
                    "completion_tokens": completion_tokens,
                    "finish_reason": finish_reason,
                    "truncated": finish_reason == "length"
                    or completion_tokens >= TRUNCATION_RATIO * max_tokens,
                }
                self.call_log.append(
                    {
                        "role": role,
                        "provider": provider.name,
                        "model": model,
                        "max_tokens": max_tokens,
                        "prompt_tokens": getattr(usage, "prompt_tokens", 0) or 0,
                        "completion_tokens": completion_tokens,
                        "finish_reason": finish_reason,
                        "seconds": round(time.monotonic() - started, 1),
                    }
                )
                return content, None, meta

        return None, last_error, None

    async def chat(
        self,
        role: str,
        system: str,
        user: str,
        *,
        temperature: float = 0.3,
        max_tokens: int | None = None,
        cache_salt: str = "",
    ) -> str:
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        last_error = None
        skip_reported: set = set()

        for target, provider in self.targets(role):
            model = target["model"]
            extra = target.get("extra") or {}
            key_model = "*" if role in self.cache_any_model else model
            key = cache_key(key_model, system, user, temperature, self.seed, cache_salt)
            path = self.cache_dir / f"{key}.txt"
            meta_path = self.cache_dir / f"{key}.meta.json"

            if not self.fresh and path.exists():
                usable, why_not = self._cached_reply_is_usable(role, key_model, meta_path)
                if usable:
                    return path.read_text()
                if why_not not in skip_reported:
                    skip_reported.add(why_not)
                    print(f"[llm] cached reply skipped, re-calling: {why_not}")

            resolved_max_tokens = self._resolve_max_tokens(role, target, max_tokens)
            text, error, meta = await self._call_with_retries(
                provider, model, messages, temperature, resolved_max_tokens, extra, role
            )
            if error is not None:
                print(f"[llm] {provider.name}/{model} failed for role {role!r}: {error}")
                last_error = error
                continue

            text = strip_think(text)
            if not text:
                if meta and meta["truncated"]:
                    print(
                        f"[llm] TRUNCATED BY max_tokens: {model}, raise max_tokens for role {role} "
                        f"(used {meta['completion_tokens']}/{resolved_max_tokens}, "
                        f"finish_reason={meta['finish_reason']})"
                    )
                    last_error = RuntimeError("truncated by max_tokens")
                else:
                    print(f"[llm] {provider.name}/{model} returned an empty reply for role {role!r}")
                    last_error = RuntimeError("empty reply")
                continue

            if meta and meta["finish_reason"] == "length":
                # Cut off at max_tokens: usable at best, but never replay it from the cache.
                print(
                    f"[llm] TRUNCATED BY max_tokens: {model}, raise max_tokens for role {role} "
                    f"(used {meta['completion_tokens']}/{resolved_max_tokens}); reply returned but not cached"
                )
                return text

            path.write_text(text)
            meta_path.write_text(json.dumps({"model": model, "provider": provider.name}))
            return text

        raise RuntimeError(f"all targets failed for role {role!r}: {last_error}")

    async def chat_json(
        self,
        role: str,
        system: str,
        user: str,
        *,
        temperature: float = 0.3,
        max_tokens: int | None = None,
        cache_salt: str = "",
    ) -> dict:
        text = await self.chat(
            role, system, user, temperature=temperature, max_tokens=max_tokens, cache_salt=cache_salt
        )
        data = extract_json(text)
        if data is not None:
            return data

        repair_user = (
            "The text below was supposed to be a single JSON object but failed to "
            "parse. Return ONLY the corrected JSON object, nothing else.\n\n" + text
        )
        repaired = await self.chat(
            role, system, repair_user, temperature=0.0, max_tokens=max_tokens, cache_salt=cache_salt
        )
        data = extract_json(repaired)
        if data is not None:
            return data
        raise ValueError(f"chat_json: could not extract JSON for role {role!r}")

    def report(self) -> dict:
        models = []
        total_usd = 0.0
        for model, stats in self.usage.items():
            price_in, price_out = self.prices.get(model, (0, 0))
            cost = (
                stats["prompt_tokens"] / 1_000_000 * price_in
                + stats["completion_tokens"] / 1_000_000 * price_out
            )
            total_usd += cost
            models.append({**{"model": model}, **stats, "cost_usd": cost})

        result = {"models": models, "total_usd": total_usd, "calls": self.call_log}
        if self.budget is not None:
            result["x402_month_to_date_usd"] = self.budget.spent()
        return result


def _first_usable_target(router: Router, targets: list, paid: bool):
    """The first target in `targets` that check() should actually probe —
    same filtering as Router.targets(), but stops at the first match instead
    of collecting the whole fallback chain, since check() pings only the
    first target: a live second target must never mask a dead first one."""
    for target in targets:
        provider = router.providers[target["provider"]]
        if not provider.enabled:
            continue
        if router.local_only and not provider.cfg.get("local"):
            continue
        if provider.cfg.get("type") == "x402" and not paid:
            continue
        return target, provider
    return None


def _missing_key_hint(router: Router, targets: list) -> str:
    missing_keys = []
    for target in targets:
        provider = router.providers[target["provider"]]
        if provider.enabled:
            continue
        key_env = provider.cfg.get("key_env")
        if key_env and key_env not in missing_keys:
            missing_keys.append(key_env)
    if missing_keys:
        return f"missing: {', '.join(missing_keys)}"
    return "filtered out by --local-only or --paid"


async def check(args) -> int:
    """Ping the first usable target of every role with a trivial prompt.

    Bypasses Router.chat()'s cache and multi-target fallback on purpose: a
    cached reply or a working second target could make a dead first-choice
    endpoint look alive.
    """
    router = Router(models_path=args.models, local_only=args.local_only, fresh=True)
    paid = getattr(args, "paid", False)

    all_ok = True
    for role, targets in router.roles.items():
        if not targets:
            print(f"{role}: no targets configured — skipped")
            continue
        found = _first_usable_target(router, targets, paid)
        if found is None:
            print(f"{role}: no usable target ({_missing_key_hint(router, targets)})")
            all_ok = False
            continue

        target, provider = found
        label = f"{target['provider']}/{target['model']}"
        try:
            response = await provider.complete(
                model=target["model"],
                messages=[
                    {"role": "system", "content": "Reply with one word."},
                    {"role": "user", "content": "Say: ready"},
                ],
                temperature=0.0,
                # Reasoning models (glm-4.7-flash, openrouter/free) spend ~150 tokens
                # thinking before a one-word answer; 10 returns an empty reply.
                max_tokens=512,
                extra=target.get("extra"),
            )
            reply = strip_think(response.choices[0].message.content or "")
            print(f"{role}: {label}: {reply[:40]!r}")
        except Exception as exc:  # noqa: BLE001 - report and keep checking other roles
            print(f"{role}: {label}: FAILED: {str(exc)[:40]}")
            all_ok = False

    return 0 if all_ok else 1
