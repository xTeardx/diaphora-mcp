"""Authoritative old-to-new function mappings from Diaphora results."""

from dataclasses import dataclass
import os
import sqlite3
import re

from ..utils.connection import get_connection
from ..utils.sqlite import (
    _RESULTS_COLUMN_MAP,
    _UNMATCHED_COLUMN_MAP,
    _detect_decimal,
    check_results_db,
    norm_addr,
    read_adaptive_table,
    get_query_addresses,
)


def canonical_address(address: str, *, decimal_database: bool = False) -> str:
    """Return a comparable lower-case hex address without ``0x``."""
    value = str(address or "").strip().lower()
    if not value:
        return ""
    if decimal_database and value.isdigit():
        # The database schema removes the hex/decimal ambiguity, so do not
        # apply norm_addr's high-address heuristic here.
        return format(int(value), "x")
    return format(int(value.removeprefix("0x"), 16), "x")


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
        self._matches = tuple(matches or ())
        old_targets, new_sources = {}, {}
        for match in self._matches:
            old_targets.setdefault(match.old_address, set()).add(match.new_address)
            new_sources.setdefault(match.new_address, set()).add(match.old_address)
        self._by_old = {
            m.old_address: m for m in self._matches
            if len(old_targets[m.old_address]) == 1 and len(new_sources[m.new_address]) == 1
            and m.match_type.lower() != "multimatch"
        }
        self._by_new = {m.new_address: m for m in self._by_old.values()}
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
        # Official CChooser.add_item/save_results serialize addresses as
        # padded hexadecimal regardless of the underlying export schema.
        mapping = cls.from_rows(
            rows,
            source_decimal=False,
            target_decimal=False,
            unmatched_primary=primary,
            unmatched_secondary=secondary,
        )
        mapping.source_decimal = source_decimal
        mapping.target_decimal = target_decimal
        return mapping

    def by_old(self, address: str, *, decimal_database=None):
        if decimal_database is None:
            decimal_database = self.source_decimal
        return self._by_old.get(canonical_address(address, decimal_database=decimal_database))

    def by_new(self, address: str, *, decimal_database=None):
        if decimal_database is None:
            decimal_database = self.target_decimal
        return self._by_new.get(canonical_address(address, decimal_database=decimal_database))

    def is_removed(self, address: str, *, decimal_database: bool = False) -> bool:
        return canonical_address(address, decimal_database=decimal_database) in self._removed

    def is_added(self, address: str, *, decimal_database: bool = False) -> bool:
        return canonical_address(address, decimal_database=decimal_database) in self._added

    @property
    def matches(self):
        return self._matches


def _database_uses_decimal_addresses(path: str) -> bool:
    if not path or not os.path.isfile(path):
        return False
    try:
        return _detect_decimal(get_connection(path))
    except Exception:
        return False


def lookup_function(db_path, address="", name=""):
    """Resolve a selector only when it selects exactly one function."""
    conn = get_connection(db_path)
    conn.row_factory = sqlite3.Row
    if address:
        addresses = get_query_addresses(conn, address)
        placeholders = ",".join("?" for _ in addresses)
        rows = conn.execute(f"SELECT * FROM functions WHERE address IN ({placeholders}) LIMIT 2", addresses).fetchall()
    elif name:
        rows = conn.execute("SELECT * FROM functions WHERE name = ? LIMIT 2", (name,)).fetchall()
    else:
        return None
    return dict(rows[0]) if len(rows) == 1 else None


def resolve_pair(db1_path, db2_path, address="", name="", address2="", name2="", match_results_path=""):
    """Resolve identity from explicit selectors, results, or unique evidence.

    Missing results rows and ambiguous matches remain unresolved. Names and
    hashes are heuristic identity evidence, never calibrated confidence.
    """
    old = lookup_function(db1_path, address, name)
    mapping = None
    if match_results_path:
        try:
            mapping = FunctionMapping.from_results(match_results_path)
        except (OSError, ValueError, sqlite3.Error) as exc:
            raise ValueError("Cannot load a valid Diaphora identity mapping") from exc
    if address2 or name2:
        return old, lookup_function(db2_path, address2, name2), {"method": "explicit_selector"}, mapping
    if not old:
        return None, None, {"method": "unresolved_primary"}, mapping
    if mapping is not None:
        match = mapping.by_old(old["address"], decimal_database=_detect_decimal(get_connection(db1_path)))
        if not match:
            return old, None, {"method": "unmatched_or_ambiguous_results"}, mapping
        new = lookup_function(db2_path, "0x" + match.new_address)
        return old, new, {"method": "diaphora_mapping", "match_type": match.match_type, "ratio": match.ratio}, mapping
    conn = get_connection(db2_path)
    conn.row_factory = sqlite3.Row
    conn_old = get_connection(db1_path)
    candidates = {}
    evidence = []

    def unique_in_primary(column, value):
        return len(conn_old.execute(f"SELECT address FROM functions WHERE {column} = ? LIMIT 2", (value,)).fetchall()) == 1

    old_name = old.get("name") or ""
    if old_name and not re.match(r"^(?:sub|loc|unk|j|fun|nullsub)_[0-9a-f]+$", old_name, re.I):
        rows = conn.execute("SELECT * FROM functions WHERE name = ? LIMIT 2", (old_name,)).fetchall()
        if len(rows) == 1 and unique_in_primary("name", old_name):
            candidates[rows[0]["address"]] = dict(rows[0])
            evidence.append("unique_name")
    for column in ("bytes_hash", "pseudocode_hash1", "pseudocode_hash2"):
        value = old.get(column)
        if not value:
            continue
        rows = conn.execute(f"SELECT * FROM functions WHERE {column} = ? LIMIT 2", (value,)).fetchall()
        if len(rows) == 1 and unique_in_primary(column, value):
            candidates[rows[0]["address"]] = dict(rows[0])
            evidence.append("unique_" + column)
    new = next(iter(candidates.values())) if len(candidates) == 1 else None
    return old, new, {"method": "heuristic_evidence" if new else "unresolved_or_conflicting_evidence", "evidence": evidence}, mapping


def compare_neighbors(db1_path, db2_path, old_neighbors, new_neighbors, mapping=None):
    """Compare edges through resolved identity; retain unresolved neighbors."""
    new_decimal = _detect_decimal(get_connection(db2_path))
    # get_callgraph already returns canonical hexadecimal addresses.
    old_set = {canonical_address(a) for a in old_neighbors}
    new_set = {canonical_address(a) for a in new_neighbors}
    translated, unknown_old = {}, []
    for old_address in old_set:
        if mapping is not None:
            match = mapping.by_old("0x" + old_address)
            target = match.new_address if match else None
        else:
            _, new, _, _ = resolve_pair(db1_path, db2_path, "0x" + old_address)
            target = canonical_address(new["address"], decimal_database=new_decimal) if new else None
        if target:
            translated[old_address] = target
        else:
            unknown_old.append(old_address)
    mapped_new = set(translated.values())
    added, unknown_new = [], []
    for new_address in new_set - mapped_new:
        if mapping is not None:
            known = mapping.by_new("0x" + new_address) is not None or mapping.is_added(new_address)
        else:
            _, old, _, _ = resolve_pair(db2_path, db1_path, "0x" + new_address)
            known = old is not None
        (added if known else unknown_new).append(new_address)
    return {
        "added": sorted(added),
        "removed": sorted(a for a, b in translated.items() if b not in new_set),
        "unchanged": len(mapped_new & new_set),
        "unknown_old": sorted(unknown_old),
        "unknown_new": sorted(unknown_new),
    }
