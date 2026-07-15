"""Authoritative old-to-new function mappings from Diaphora results."""

from dataclasses import dataclass
import os
import sqlite3

from ..utils.connection import get_connection
from ..utils.sqlite import (
    _RESULTS_COLUMN_MAP,
    _UNMATCHED_COLUMN_MAP,
    _detect_decimal,
    check_results_db,
    norm_addr,
    read_adaptive_table,
)


def canonical_address(address: str, *, decimal_database: bool = False) -> str:
    """Return a comparable lower-case hex address without ``0x``."""
    value = str(address or "").strip().lower()
    if not value:
        return ""
    if decimal_database and value.isdigit():
        return norm_addr(value, True)
    return norm_addr(value, False)


@dataclass(frozen=True)
class FunctionMatch:
    """One Diaphora match and the evidence attached to it."""

    old_address: str
    new_address: str
    match_type: str = ""
    ratio: float = 0.0
    old_name: str = ""
    new_name: str = ""


class FunctionMapping:
    """Bidirectional address mapping for two exported databases."""

    def __init__(self, matches=None, removed=None, added=None,
                 source_decimal=False, target_decimal=False):
        self._by_old = {m.old_address: m for m in (matches or [])}
        self._by_new = {m.new_address: m for m in (matches or [])}
        self._removed = set(removed or ())
        self._added = set(added or ())
        self.source_decimal = source_decimal
        self.target_decimal = target_decimal

    @classmethod
    def from_rows(
        cls,
        rows,
        *,
        source_decimal: bool = False,
        target_decimal: bool = False,
        unmatched_primary=None,
        unmatched_secondary=None,
    ):
        matches = []
        for row in rows or ():
            old = canonical_address(row.get("address"), decimal_database=source_decimal)
            new = canonical_address(row.get("address2"), decimal_database=target_decimal)
            if not old or not new:
                continue
            try:
                ratio = float(row.get("ratio") or 0.0)
            except (TypeError, ValueError):
                ratio = 0.0
            matches.append(
                FunctionMatch(
                    old_address=old,
                    new_address=new,
                    match_type=str(row.get("type") or ""),
                    ratio=ratio,
                    old_name=str(row.get("name") or ""),
                    new_name=str(row.get("name2") or ""),
                )
            )

        removed = {
            canonical_address(row.get("address"), decimal_database=source_decimal)
            for row in (unmatched_primary or ())
            if row.get("address")
        }
        added = {
            canonical_address(row.get("address"), decimal_database=target_decimal)
            for row in (unmatched_secondary or ())
            if row.get("address")
        }
        return cls(matches, removed, added, source_decimal, target_decimal)

    @classmethod
    def from_results(cls, results_path: str):
        """Load mapping and address-base metadata from a Diaphora result file."""
        if not os.path.isfile(results_path):
            raise FileNotFoundError(results_path)
        if (error := check_results_db(results_path)):
            raise ValueError(error)

        conn = get_connection(results_path)
        conn.row_factory = sqlite3.Row
        config = dict(conn.execute("SELECT * FROM config").fetchone() or {})
        source_path = config.get("main_db") or config.get("primary_database") or ""
        target_path = config.get("diff_db") or config.get("secondary_database") or ""

        source_decimal = _database_uses_decimal_addresses(source_path)
        target_decimal = _database_uses_decimal_addresses(target_path)
        rows = read_adaptive_table(
            results_path, _RESULTS_COLUMN_MAP, "results", row_factory=sqlite3.Row
        )
        unmatched_primary = read_adaptive_table(
            results_path, _UNMATCHED_COLUMN_MAP, "unmatched", row_factory=sqlite3.Row
        )
        primary = [r for r in unmatched_primary if r.get("type") == "primary"]
        secondary = [r for r in unmatched_primary if r.get("type") == "secondary"]
        return cls.from_rows(
            rows,
            source_decimal=source_decimal,
            target_decimal=target_decimal,
            unmatched_primary=primary,
            unmatched_secondary=secondary,
        )

    def by_old(self, address: str, *, decimal_database: bool = False):
        return self._by_old.get(canonical_address(address, decimal_database=decimal_database))

    def by_new(self, address: str, *, decimal_database: bool = False):
        return self._by_new.get(canonical_address(address, decimal_database=decimal_database))

    def is_removed(self, address: str, *, decimal_database: bool = False) -> bool:
        return canonical_address(address, decimal_database=decimal_database) in self._removed

    def is_added(self, address: str, *, decimal_database: bool = False) -> bool:
        return canonical_address(address, decimal_database=decimal_database) in self._added

    @property
    def matches(self):
        return tuple(self._by_old.values())


def _database_uses_decimal_addresses(path: str) -> bool:
    if not path or not os.path.isfile(path):
        return False
    try:
        return _detect_decimal(get_connection(path))
    except Exception:
        return False
