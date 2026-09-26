"""Upstream detection and fetch.

A target that is a fork of a known project (MakerDAO dss, OpenZeppelin, ...) should be compared
against that project's REAL source, not against the model's memory of it. This module answers two
questions: "which known upstream does this target derive from?" (detect) and "give me its source"
(fetch). The literal comparison itself lives in stmtdiff.py.

Registry data is upstreams.yaml, not code. The network is only touched inside `fetch`, through an
injectable `fetcher`, so tests never make a real request.
"""

import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

import yaml

DEFAULT_REGISTRY = Path(__file__).resolve().parent.parent / "upstreams.yaml"
_DOC_NAMES = ("README", "README.md", "readme.md", "DESIGN.md", "ARCHITECTURE.md", "SPEC.md")
_TEXT_CAP = 200_000  # chars of README/docs/comments scanned for detection


@dataclass
class Upstream:
    key: str
    name: str
    detect: list
    min_hits: int
    sources: list  # [{repo, ref, files: [...]}]
    contract_hints: dict = field(default_factory=dict)
    function_aliases: dict = field(default_factory=dict)
    reference_params: list = field(default_factory=list)
    vendored_only: bool = False

    def raw_urls(self):
        """[(path_in_repo, url)] for every source file."""
        return [
            (path, f"https://raw.githubusercontent.com/{src['repo']}/{src.get('ref', 'master')}/{path}")
            for src in self.sources
            for path in src.get("files", [])
        ]


def load_registry(path=None) -> dict:
    raw = yaml.safe_load(Path(path or DEFAULT_REGISTRY).read_text(encoding="utf-8")) or {}
    registry = {}
    for key, cfg in (raw.get("upstreams") or {}).items():
        registry[key] = Upstream(
            key=key,
            name=cfg.get("name", key),
            detect=list(cfg.get("detect", [])),
            min_hits=int(cfg.get("min_hits", 2)),
            sources=list(cfg.get("sources", [])),
            contract_hints=dict(cfg.get("contract_hints") or {}),
            function_aliases=dict(cfg.get("function_aliases") or {}),
            reference_params=list(cfg.get("reference_params") or []),
            vendored_only=bool(cfg.get("vendored_only", False)),
        )
    return registry


_COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)


def gather_target_text(root, files=None) -> str:
    """README/docs at the target root plus every comment in its Solidity sources, capped.

    Comments are where forks admit their lineage ("adapted from Maker's Vat"), so they count as
    documentation for detection purposes even when the README says nothing."""
    root = Path(root)
    parts = []
    for name in _DOC_NAMES:
        p = root / name
        if p.is_file():
            parts.append(p.read_text(encoding="utf-8", errors="replace"))
    docs = root / "docs"
    if docs.is_dir():
        for p in sorted(docs.rglob("*.md"))[:20]:
            parts.append(p.read_text(encoding="utf-8", errors="replace"))
    for src in files or []:
        text = "\n".join(src.lines) if hasattr(src, "lines") else str(src)
        parts.append("\n".join(_COMMENT_RE.findall(text)))
    return "\n".join(parts)[:_TEXT_CAP]


def detect(text: str, registry: dict) -> list:
    """[(Upstream, hits)] for every upstream whose distinct detect-patterns match at least
    `min_hits` times, strongest first."""
    found = []
    for up in registry.values():
        hits = sum(1 for pat in up.detect if re.search(pat, text, re.IGNORECASE))
        if hits >= up.min_hits:
            found.append((up, hits))
    return sorted(found, key=lambda pair: -pair[1])


def _http_fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "hound-upstream-diff"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - fixed https raw.githubusercontent.com URLs
        return resp.read().decode("utf-8", errors="replace")


def fetch(up: Upstream, cache_dir, fetcher=None) -> tuple:
    """Upstream sources, cached under cache_dir/upstream/<key>/<path>. Returns
    ({path: source}, [failure messages]). A file that cannot be fetched is reported, never
    guessed: a missing upstream file means "no comparison", not "no deviation"."""
    fetcher = fetcher or _http_fetch
    base = Path(cache_dir) / "upstream" / up.key
    sources, failures = {}, []
    for path, url in up.raw_urls():
        cached = base / path
        if cached.is_file():
            sources[path] = cached.read_text(encoding="utf-8")
            continue
        try:
            text = fetcher(url)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            failures.append(f"{path}: {exc}")
            continue
        cached.parent.mkdir(parents=True, exist_ok=True)
        cached.write_text(text, encoding="utf-8")
        sources[path] = text
    return sources, failures
