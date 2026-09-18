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


def cache_key(model: str, system: str, user: str, temperature: float, seed) -> str:
    payload = json.dumps([model, system, user, temperature, seed], sort_keys=True)
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
    ):
        config = yaml.safe_load(Path(models_path).read_text())
        self.local_only = local_only
        self.seed = seed
        self.fresh = fresh
        self.budget = budget

        self.roles = config["roles"]
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

    def _record_usage(self, model: str, response):
        stats = self.usage.setdefault(
            model, {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0}
        )
        stats["calls"] += 1
        usage = getattr(response, "usage", None)
        if usage is not None:
            stats["prompt_tokens"] += getattr(usage, "prompt_tokens", 0) or 0
            stats["completion_tokens"] += getattr(usage, "completion_tokens", 0) or 0

    async def _call_with_retries(self, provider, model, messages, temperature, max_tokens, extra):
        cur_temperature = temperature
        retried_without_temperature = False
        last_error = None

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
                    await asyncio.sleep(min(60, 4 * 2**attempt))
                    continue
                break
            else:
                self._record_usage(model, response)
                content = response.choices[0].message.content or ""
                return content, None

        return None, last_error

    async def chat(
        self,
        role: str,
        system: str,
        user: str,
        *,
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> str:
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        last_error = None

        for target, provider in self.targets(role):
            model = target["model"]
            extra = target.get("extra") or {}
            key = cache_key(model, system, user, temperature, self.seed)
            path = self.cache_dir / f"{key}.txt"

            if not self.fresh and path.exists():
                return path.read_text()

            text, error = await self._call_with_retries(
                provider, model, messages, temperature, max_tokens, extra
            )
            if error is not None:
                print(f"[llm] {provider.name}/{model} failed for role {role!r}: {error}")
                last_error = error
                continue

            text = strip_think(text)
            if not text:
                print(f"[llm] {provider.name}/{model} returned an empty reply for role {role!r}")
                last_error = RuntimeError("empty reply")
                continue

            path.write_text(text)
            return text

        raise RuntimeError(f"all targets failed for role {role!r}: {last_error}")

    async def chat_json(
        self,
        role: str,
        system: str,
        user: str,
        *,
        temperature: float = 0.3,
        max_tokens: int = 2048,
    ) -> dict:
        text = await self.chat(role, system, user, temperature=temperature, max_tokens=max_tokens)
        data = extract_json(text)
        if data is not None:
            return data

        repair_user = (
            "The text below was supposed to be a single JSON object but failed to "
            "parse. Return ONLY the corrected JSON object, nothing else.\n\n" + text
        )
        repaired = await self.chat(role, system, repair_user, temperature=0.0, max_tokens=max_tokens)
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

        result = {"models": models, "total_usd": total_usd}
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
                max_tokens=10,
                extra=target.get("extra"),
            )
            reply = strip_think(response.choices[0].message.content or "")
            print(f"{role}: {label}: {reply[:40]!r}")
        except Exception as exc:  # noqa: BLE001 - report and keep checking other roles
            print(f"{role}: {label}: FAILED: {str(exc)[:40]}")
            all_ok = False

    return 0 if all_ok else 1
