"""One aerleon Naming per definitions directory, shared across calls.

Building a Naming parses the whole def tree — the
dominant per-invocation cost when a single process makes many diffs or applies
(firru mass, a batch replay). Naming is read-only once built (callers only
resolve tokens), so caching by directory is safe. A fresh process starts with
an empty cache, so nothing is stale between runs.
"""

from functools import lru_cache

from aerleon.lib import naming


@lru_cache(maxsize=None)
def cached_naming(defs_dir: str):
    from firru.defs_dir import resolve
    return naming.Naming(resolve(defs_dir))
