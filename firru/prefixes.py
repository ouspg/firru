"""Longest-prefix match without a compiled dependency.

`PrefixTree(32)` / `PrefixTree(128)` stand in for `pytricia.PyTricia`, for the
part of its interface firru uses: insert or assign a prefix, ask whether one is
stored exactly, look up the longest stored prefix containing an address or a
prefix, delete one, and `in` / `len`. pytricia publishes no wheel for current
Pythons, so it made every install need a C compiler; this is the only thing
firru used it for.

The table is one dict per prefix length that occurs, keyed by the network as
an integer, and a lookup tries those lengths longest first. Definitions use a
dozen or so lengths, so a lookup is a dozen dict probes. Address parsing is
`socket.inet_pton`, which is several times faster than `ipaddress` and was
most of the cost; lookups of plain addresses are cached, and any change to the
table clears the cache. On a definitions set of some 6,000 prefixes a cached
lookup takes about 0.2 us and an uncached one about 1.7 us, against
pytricia's 0.7 us.
"""

import socket

_CACHE_MAX = 1 << 18


class PrefixTree:
    """A prefix -> value table with longest-prefix match, for one family."""

    def __init__(self, bits=32):
        if bits not in (32, 128):
            raise ValueError(f"bits must be 32 or 128, not {bits}")
        self._bits = bits
        self._af = socket.AF_INET if bits == 32 else socket.AF_INET6
        self._by_len = {}          # prefix length -> {network int: value}
        self._lens = []            # the lengths present, longest first
        self._cache = {}           # address string -> value (or _MISS)

    # -- parsing -------------------------------------------------------------

    def _parse(self, key):
        """(network int, prefix length) for an address or a prefix."""
        s = str(key)
        addr, slash, plen = s.partition("/")
        try:
            x = int.from_bytes(socket.inet_pton(self._af, addr), "big")
        except OSError:
            raise ValueError(f"not an IPv{4 if self._bits == 32 else 6} "
                             f"address or prefix: {s!r}") from None
        if slash:
            try:
                n = int(plen)
            except ValueError:
                raise ValueError(f"bad prefix length in {s!r}") from None
            if not 0 <= n <= self._bits:
                raise ValueError(f"bad prefix length in {s!r}")
        else:
            n = self._bits
        shift = self._bits - n
        return (x >> shift) << shift, n

    # -- changes -------------------------------------------------------------

    def insert(self, key, value):
        x, n = self._parse(key)
        table = self._by_len.get(n)
        if table is None:
            table = self._by_len[n] = {}
            self._lens = sorted(self._by_len, reverse=True)
        table[x] = value
        self._cache.clear()

    __setitem__ = insert

    def delete(self, key):
        x, n = self._parse(key)
        table = self._by_len.get(n)
        if table is None or x not in table:
            raise KeyError(key)
        del table[x]
        if not table:
            del self._by_len[n]
            self._lens = sorted(self._by_len, reverse=True)
        self._cache.clear()

    __delitem__ = delete

    # -- queries -------------------------------------------------------------

    def has_key(self, key):
        """Whether exactly this prefix is stored."""
        x, n = self._parse(key)
        return x in self._by_len.get(n, ())

    def _match(self, x, n):
        for length in self._lens:
            if length > n:
                continue
            shift = self._bits - length
            hit = self._by_len[length].get((x >> shift) << shift, _MISS)
            if hit is not _MISS:
                return hit
        return _MISS

    def get(self, key, default=None):
        """The value of the longest stored prefix containing `key` (an address
        or a prefix), or `default`."""
        s = str(key)
        if "/" not in s:
            hit = self._cache.get(s, _NOT_CACHED)
            if hit is _NOT_CACHED:
                hit = self._match(*self._parse(s))
                if len(self._cache) >= _CACHE_MAX:
                    self._cache.clear()
                self._cache[s] = hit
        else:
            hit = self._match(*self._parse(s))
        return default if hit is _MISS else hit

    def __getitem__(self, key):
        hit = self.get(key, _MISS)
        if hit is _MISS:
            raise KeyError(key)
        return hit

    def __contains__(self, key):
        try:
            return self.get(key, _MISS) is not _MISS
        except ValueError:
            return False

    def __len__(self):
        return sum(len(t) for t in self._by_len.values())


_MISS = object()
_NOT_CACHED = object()
