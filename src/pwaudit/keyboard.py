"""Keyboard adjacency, for spotting walks such as qwerty or 1qaz2wsx."""

from __future__ import annotations

from functools import cache

_ROWS = ("1234567890-=", "qwertyuiop[]", "asdfghjkl;'", "zxcvbnm,./")
_SHIFTED = '!@#$%^&*()_+QWERTYUIOP{}ASDFGHJKL:"ZXCVBNM<>?'
_UNSHIFTED = "1234567890-=qwertyuiop[]asdfghjkl;'zxcvbnm,./"
_SHIFT_MAP = dict(zip(_SHIFTED, _UNSHIFTED * 1, strict=False))
for _u in "QWERTYUIOPASDFGHJKLZXCVBNM":
    _SHIFT_MAP[_u] = _u.lower()
for _s, _b in zip("!@#$%^&*()_+", "1234567890-=", strict=True):
    _SHIFT_MAP[_s] = _b
for _s, _b in zip('{}:"<>?', "[];'" + ",./", strict=False):
    _SHIFT_MAP.setdefault(_s, _b)


class Keyboard:
    """Neighbours of each key on a staggered keyboard: left, right, and the two rows above and
    below (a key touches two neighbours in each adjacent row)."""

    def __init__(self, rows: tuple[str, ...], stagger: tuple[float, ...]) -> None:
        self.pos: dict[str, tuple[int, int]] = {}
        for r, row in enumerate(rows):
            for c, ch in enumerate(row):
                self.pos[ch] = (r, c)
        self.rows = rows
        self.stagger = stagger
        self.adj: dict[str, list[str]] = {}
        for ch, (r, c) in self.pos.items():
            neighbours: list[str] = []
            for dr, dc in ((0, -1), (0, 1)):
                self._add(neighbours, r + dr, c + dc)
            for dr in (-1, 1):
                other = r + dr
                if not 0 <= other < len(rows):
                    continue
                offset = stagger[other] - stagger[r]
                base = c - offset
                for cc in (int(base // 1), int(base // 1) + 1):
                    self._add(neighbours, other, cc)
            self.adj[ch] = neighbours

    def _add(self, out: list[str], r: int, c: int) -> None:
        if 0 <= r < len(self.rows) and 0 <= c < len(self.rows[r]):
            out.append(self.rows[r][c])

    @staticmethod
    def base(ch: str) -> str:
        return _SHIFT_MAP.get(ch, ch.lower())

    def is_shifted(self, ch: str) -> bool:
        return ch in _SHIFT_MAP and _SHIFT_MAP[ch] != ch

    def direction(self, a: str, b: str) -> int:
        """Index of the neighbour direction from a to b, or -1 when they are not adjacent."""
        a, b = self.base(a), self.base(b)
        if a not in self.adj or a == b:
            return -1
        try:
            return self.adj[a].index(b)
        except ValueError:
            return -1


QWERTY = Keyboard(_ROWS, (0.0, 0.5, 0.75, 1.25))


@cache
def graph_stats(name: str) -> tuple[int, float]:
    """(number of keys, average number of neighbours)."""
    kb = QWERTY
    return len(kb.adj), sum(len(v) for v in kb.adj.values()) / len(kb.adj)
