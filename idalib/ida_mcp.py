"""IDA Pro MCP Plugin Loader

This file serves as the entry point for IDA Pro's plugin system.
It loads the actual implementation from the ida_mcp package.
"""

import sys
import os
import re
import json
import uuid
import sqlite3
import threading
import hashlib
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import idaapi
import ida_kernwin
import ida_netnode

if TYPE_CHECKING:
    from . import ida_mcp


NETNODE_AUTOSTART = "$ ida_mcp.autostart"
NETNODE_CONFIG = "$ ida_mcp.config"
_ALT_PORT = 0  # altval index for the persisted port (0 = not set)
_ALT_PERSIST = 1  # altval index for the "save host/port" preference
_SUP_HOST = 0  # supval index for the persisted host


def _get_autostart() -> bool:
    """Read the autostart preference from the IDB. Defaults to True."""
    node = ida_netnode.netnode(NETNODE_AUTOSTART)
    val = node.altval(0)  # 0 = not set, 1 = off, 2 = on
    return val != 1


def _set_autostart(enabled: bool):
    """Persist the autostart preference into the IDB."""
    node = ida_netnode.netnode(NETNODE_AUTOSTART, 0, True)
    node.altset(0, 1 if not enabled else 2)


def _get_port(default: int) -> int:
    """Read the persisted server port from the IDB. Defaults to `default`."""
    node = ida_netnode.netnode(NETNODE_CONFIG)
    val = node.altval(_ALT_PORT)  # 0 = not set
    return val if val != 0 else default


def _set_port(port: int):
    """Persist the server port into the IDB."""
    node = ida_netnode.netnode(NETNODE_CONFIG, 0, True)
    node.altset(_ALT_PORT, port)


def _get_host(default: str) -> str:
    """Read the persisted server host from the IDB. Defaults to `default`."""
    node = ida_netnode.netnode(NETNODE_CONFIG)
    val = node.supstr(_SUP_HOST)
    return val if val else default


def _set_host(host: str):
    """Persist the server host into the IDB."""
    node = ida_netnode.netnode(NETNODE_CONFIG, 0, True)
    node.supset(_SUP_HOST, host)


def _get_persist() -> bool:
    """Read the 'save host/port' preference from the IDB. Defaults to True."""
    node = ida_netnode.netnode(NETNODE_CONFIG)
    val = node.altval(_ALT_PERSIST)  # 0 = not set, 1 = off, 2 = on
    return val != 1


def _set_persist(enabled: bool):
    """Persist the 'save host/port' preference into the IDB."""
    node = ida_netnode.netnode(NETNODE_CONFIG, 0, True)
    node.altset(_ALT_PERSIST, 2 if enabled else 1)


def _clear_endpoint():
    """Forget any persisted host/port so the next load uses the defaults."""
    node = ida_netnode.netnode(NETNODE_CONFIG, 0, True)
    node.altdel(_ALT_PORT)
    node.supdel(_SUP_HOST)


def unload_package(package_name: str):
    """Remove every module that belongs to the package from sys.modules."""
    to_remove = [
        mod_name
        for mod_name in sys.modules
        if mod_name == package_name or mod_name.startswith(package_name + ".")
    ]
    for mod_name in to_remove:
        del sys.modules[mod_name]


# ---------------------------------------------------------------------------
# Diaphora export — full IDB → SQLite export via IDAPython
# ---------------------------------------------------------------------------

DIAPHORA_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS functions (
    address         TEXT PRIMARY KEY,
    name            TEXT,
    size            INTEGER,
    complexity      INTEGER,
    instructions    INTEGER,
    prototype       TEXT,
    pseudocode      TEXT,
    asm             TEXT,
    bytes           TEXT,
    md5             TEXT,
    md5_min         TEXT,
    type            TEXT
);
CREATE TABLE IF NOT EXISTS calls (
    caller          TEXT,
    callee          TEXT
);
CREATE TABLE IF NOT EXISTS basic_blocks (
    address         TEXT,
    block_start     TEXT,
    size            INTEGER
);
CREATE TABLE IF NOT EXISTS strings (
    address         TEXT,
    string          TEXT,
    xref_addr       TEXT
);
CREATE TABLE IF NOT EXISTS constants (
    address         TEXT,
    constant        INTEGER,
    operand         INTEGER
);
CREATE TABLE IF NOT EXISTS imports (
    address         TEXT,
    import_name     TEXT,
    module          TEXT
);
CREATE TABLE IF NOT EXISTS structures (
    name            TEXT PRIMARY KEY,
    size            INTEGER,
    members         TEXT,
    declaration     TEXT
);
CREATE TABLE IF NOT EXISTS enums (
    name            TEXT PRIMARY KEY,
    bitfield        INTEGER,
    members         TEXT
);
CREATE TABLE IF NOT EXISTS comments (
    address         TEXT,
    comment         TEXT,
    type            TEXT
);
CREATE TABLE IF NOT EXISTS metadata (
    key             TEXT PRIMARY KEY,
    value           TEXT
);
"""


_IMPORT_CACHE = None


def _build_import_cache():
    """Build {ea: (import_name, module_name)} for all imported functions."""
    global _IMPORT_CACHE
    if _IMPORT_CACHE is not None:
        return _IMPORT_CACHE
    _IMPORT_CACHE = {}
    try:
        import ida_nalt
        nimps = ida_nalt.get_import_module_qty()
        for mod_idx in range(nimps):
            mod_name = ida_nalt.get_import_module_name(mod_idx)
            if not mod_name:
                continue
            entries = []
            def _imp_cb(ea, name, entries=entries, mod_name=mod_name):
                entries.append((ea, name))
                return True
            ida_nalt.enum_import_names(mod_idx, _imp_cb)
            for ea, name in entries:
                _IMPORT_CACHE[ea] = (name or "", mod_name)
    except Exception:
        pass
    return _IMPORT_CACHE


def _classify_function(func_ea, size, blocks, callees):
    """Classify function as thunk/leaf/wrapper/dispatcher/complex."""
    try:
        if size <= 8:
            return "thunk"
        n_callees = sum(1 for _ in callees) if callees else 0
        n_blocks = len(blocks) if blocks else 0
        if n_callees == 0:
            return "leaf"
        if n_callees <= 2 and n_blocks <= 3:
            return "wrapper"
        if n_blocks > 20:
            return "complex"
        return "dispatcher"
    except Exception:
        return "unknown"


def _export_diaphora(
    output_path: str,
    opts: dict,
    progress: "idaapi.timeldk_progress_t | None" = None,
    task_id: str | None = None,
) -> str:
    """Export the currently open IDB to Diaphora-format SQLite.

    Designed to run on a **background thread**.  Uses ``execute_sync(MFF_READ)``
    only for brief IDAPython data collection (one batch at a time), keeping
    the main IDA thread responsive between batches.

    Args:
        output_path: Path for the output .sqlite file.
        opts: Dict with optional keys:
            - use_decompiler (bool): Include Hex-Rays pseudocode.
            - summaries_only (bool): Skip detailed ASM/bytes/blocks.
        progress: Optional progress indicator; checked for user cancellation
            *between* batches (on the background thread).

    Returns:
        The output path on success.

    Raises:
        RuntimeError on failure or user cancellation ("cancelled").
    """
    import idautils
    import idc
    import ida_funcs
    import ida_gdl
    import ida_nalt
    import ida_bytes
    import ida_xref
    import ida_hexrays
    try:
        import ida_struct
    except ImportError:
        ida_struct = None
    try:
        import ida_enum
    except ImportError:
        ida_enum = None
    import ida_typeinf
    import ida_ida

    use_decompiler = opts.get("use_decompiler", False)
    summaries_only = opts.get("summaries_only", False)
    BATCH_SIZE = 50

    # ==================================================================
    # Phase 1 — quick data collection on the main thread (one sync call)
    # ==================================================================
    _state: dict = {}

    def _phase1():
        _state["compiler"] = ""
        try:
            _state["compiler"] = ida_typeinf.get_compiler_name(ida_ida.inf_get_compiler())
        except Exception:
            pass
        _state["root_filename"] = ida_nalt.get_root_filename() or ""
        md5_val = ""
        try:
            m = ida_nalt.retrieve_input_file_md5()
            if m:
                md5_val = m.hex()
        except Exception:
            try:
                m = idc.GetInputMD5()
                if m:
                    md5_val = m
            except Exception:
                pass
        _state["md5"] = md5_val
        _state["imagebase"] = hex(idaapi.get_imagebase())
        _state["is64"] = idaapi.inf_is_64bit()

        # Structures
        structs = []
        struct_qty = ida_struct.get_struc_qty() if ida_struct is not None else 0
        for idx in range(struct_qty):
            try:
                sptr = ida_struct.get_struc_by_idx(idx)
                if not sptr:
                    continue
                name = ida_struct.get_struc_name(sptr.id) or ""
                members = []
                for j in range(ida_struct.get_struc_member_qty(sptr)):
                    m = ida_struct.get_struc_member_by_idx(sptr, j)
                    if not m:
                        continue
                    try:
                        tinfo = ida_struct.get_member_tinfo(m)
                        tstr = tinfo.dstr() if tinfo else ""
                    except Exception:
                        tstr = ""
                    members.append({
                        "offset": getattr(m, "soff", 0),
                        "name":   ida_struct.get_member_name(m.id) or "",
                        "size":   getattr(m, "size", 0),
                        "type":   tstr,
                    })
                decl = ""
                try:
                    tid = ida_struct.get_struc_id(name) if ida_struct is not None else idaapi.BADNODE
                    if tid != idaapi.BADNODE:
                        decl = ida_typeinf.get_type(tid) or ""
                except Exception:
                    pass
                structs.append({
                    "name": name,
                    "size": getattr(sptr, "size", 0),
                    "members": members,
                    "decl": decl,
                })
            except Exception:
                continue
        _state["structs"] = structs

        # Enums
        enums = []
        enum_qty = ida_enum.get_enum_qty() if ida_enum is not None else 0
        for idx in range(enum_qty):
            try:
                eid = ida_enum.get_enum_by_idx(idx)
                name = ida_enum.get_enum_name(eid) or ""
                bf = ida_enum.is_bf(eid)
                members = []
                for bit in range(ida_enum.get_enum_size(eid) * 8):
                    cid = ida_enum.get_first_enum_member(eid, bit)
                    if cid != ida_enum.DEFMASK:
                        members.append({
                            "name":  ida_enum.get_enum_member_name(cid) or "",
                            "value": ida_enum.get_enum_member_value(cid),
                        })
                enums.append({"name": name, "bf": 1 if bf else 0, "members": members})
            except Exception:
                continue
        _state["enums"] = enums

        # Import cache
        _state["imp_cache"] = _build_import_cache()

        # Function addresses + comments
        addrs = []
        comments = []
        for func_ea in idautils.Functions():
            try:
                func = ida_funcs.get_func(func_ea)
                if not func:
                    continue
                addrs.append(func.start_ea)
                # Function comments
                comment = idc.get_func_comment(func_ea)
                if comment:
                    comments.append((hex(func_ea), comment, "function"))
                # Per-instruction comments
                for head in idautils.Heads(func.start_ea, func.end_ea):
                    for ctype, label in [(0, "regular"), (1, "repeatable")]:
                        try:
                            text = idc.get_cmt(head, ctype)
                            if text:
                                comments.append((hex(head), text, label))
                        except Exception:
                            pass
            except Exception:
                continue
        _state["addrs"] = addrs
        _state["comments"] = comments
        _state["total"] = len(addrs)

    idaapi.execute_sync(_phase1, idaapi.MFF_READ)

    # ==================================================================
    # Write Phase 1 data to SQLite  (background thread, NO IDA calls)
    # ==================================================================
    try:
        if os.path.exists(output_path):
            os.remove(output_path)
    except Exception:
        pass
    conn = sqlite3.connect(output_path)
    cur = conn.cursor()
    cur.executescript(DIAPHORA_SCHEMA_SQL)

    # Metadata
    arch = "x64" if _state["is64"] else "x86"
    cur.executemany("INSERT OR IGNORE INTO metadata VALUES (?, ?)", [
        ("module",   _state["root_filename"]),
        ("md5",      _state["md5"]),
        ("base",     _state["imagebase"]),
        ("arch",     arch),
        ("compiler", _state["compiler"]),
    ])

    # Structures
    for s in _state["structs"]:
        cur.execute(
            "INSERT OR REPLACE INTO structures VALUES (?, ?, ?, ?)",
            (s["name"], s["size"], json.dumps(s["members"]), s["decl"]),
        )

    # Enums
    for e in _state["enums"]:
        cur.execute(
            "INSERT OR REPLACE INTO enums VALUES (?, ?, ?)",
            (e["name"], e["bf"], json.dumps(e["members"])),
        )

    # Comments
    for (addr, text, ctype) in _state["comments"]:
        cur.execute("INSERT INTO comments VALUES (?, ?, ?)", (addr, text, ctype))

    imp_cache = _state["imp_cache"]
    addrs = _state["addrs"]
    total = _state["total"]

    # ==================================================================
    # Phase 2 — batch function processing
    # Each batch collects data via a brief execute_sync call, then the
    # background thread writes to SQLite while the main thread is free.
    # ==================================================================
    conn.commit()  # flush Phase 1 before starting batch inserts

    for batch_start in range(0, total, BATCH_SIZE):
        batch_slice = addrs[batch_start:batch_start + BATCH_SIZE]
        batch_funcs: list[dict] = []

        def _collect_batch():
            for addr in batch_slice:
                try:
                    func = ida_funcs.get_func(addr)
                    if not func:
                        continue
                    data = _collect_one(func, use_decompiler, summaries_only)
                    batch_funcs.append(data)
                except Exception:
                    continue

        idaapi.execute_sync(_collect_batch, idaapi.MFF_READ)

        # Write batch to SQLite (background thread, no IDA calls)
        for data in batch_funcs:
            _write_one(cur, data, imp_cache)

        # Cancel check (runs on background thread — safe)
        if progress and progress.cancelled():
            conn.close()
            try:
                os.remove(output_path)
            except OSError:
                pass
            raise RuntimeError("cancelled")

        # Progress
        done = batch_start + len(batch_slice)
        if done % 200 == 0 or done >= total:
            print(f"[Diaphora] {min(done, total)}/{total}")
            if task_id:
                EXPORT_TASKS[task_id] = {
                    "progress": min(done, total),
                    "total": total,
                    "percentage": int(min(done, total) * 100 / total)
                }

    conn.commit()
    conn.close()
    return output_path


def _collect_one(func, use_decompiler, summaries_only):
    """Collect all Diaphora-relevant data for one function.

    Must be called on the main IDA thread (inside execute_sync).
    Returns a plain dict — no IDAPython objects.
    """
    import idautils
    import idc
    import ida_funcs
    import ida_gdl
    import ida_hexrays
    import ida_bytes
    import ida_ida
    import hashlib

    func_ea = func.start_ea
    size = func.end_ea - func.start_ea
    name = idc.get_func_name(func_ea) or ""

    # CFG
    complexity = 0
    blocks_raw = [] if not summaries_only else None
    callee_set: set = set()
    if not summaries_only:
        try:
            blocks_raw = list(ida_gdl.FlowChart(func))
            complexity = len(blocks_raw)
        except Exception:
            pass

    # Callees
    callee_list = []
    try:
        callee_list = list(idautils.CodeRefsFrom(func_ea, 0))
        for ref in callee_list:
            target = idc.get_func(ref)
            if target:
                callee_set.add(target.start_ea)
    except Exception:
        pass

    ftype = _classify_function(func_ea, size, blocks_raw, callee_list)

    # Pseudocode
    pseudocode = ""
    if use_decompiler:
        try:
            cfunc = ida_hexrays.decompile(func_ea)
            pseudocode = str(cfunc)
        except Exception:
            pass

    # Assembly + bytes
    asm_lines = []
    asm_count = 0
    raw_bytes = b""
    if not summaries_only:
        for head in idautils.Heads(func.start_ea, func.end_ea):
            try:
                line = idc.generate_disasm_line(head, 0)
                if line:
                    asm_lines.append(line)
                asm_count += 1
            except Exception:
                asm_lines.append("?")
                asm_count += 1
        try:
            raw_bytes = ida_bytes.get_bytes(func.start_ea, size) or b""
        except Exception:
            pass

    asm = "\n".join(asm_lines)
    raw_hex = raw_bytes.hex()
    md5_hash = hashlib.md5(raw_bytes).hexdigest() if raw_bytes else ""

    # Mnemonic-only hash
    md5_min = ""
    if asm_lines:
        try:
            mnemonics = []
            for head in idautils.Heads(func.start_ea, func.end_ea):
                try:
                    line = idc.generate_disasm_line(head, 0) or ""
                    mnem = line.split()[0] if line.split() else ""
                    mnemonics.append(mnem)
                except Exception:
                    pass
            md5_min = hashlib.md5("|".join(mnemonics).encode()).hexdigest()
        except Exception:
            pass

    # Prototype
    proto = ""
    try:
        proto = idc.get_type(func_ea) or ""
    except Exception:
        pass

    # Strings referenced by this function
    strings = []
    try:
        for ref in idautils.DataRefsFrom(func_ea):
            s = idc.get_strlit_contents(ref)
            if s:
                strings.append({
                    "string": s.decode("utf-8", errors="replace"),
                    "xref": hex(ref),
                })
    except Exception:
        pass

    # Constants
    constants = []
    if not summaries_only:
        try:
            for head in idautils.Heads(func.start_ea, func.end_ea):
                for op_n in range(6):
                    op_val = idc.get_operand_value(head, op_n)
                    if op_val != 0 and op_val != idaapi.BADADDR:
                        # Cast to signed 64-bit integer to prevent SQLite overflow
                        signed_val = (op_val + 2**63) % 2**64 - 2**63
                        constants.append({"value": signed_val, "op": op_n})
        except Exception:
            pass

    # Call targets (for imports)
    call_targets = []
    for ref in callee_list:
        call_targets.append(ref)

    return {
        "ea":       hex(func_ea),
        "name":     name,
        "size":     size,
        "complex":  complexity,
        "asm_cnt":  asm_count,
        "proto":    proto,
        "pseudo":   pseudocode,
        "asm":      asm,
        "bytes":    raw_hex,
        "md5":      md5_hash,
        "md5_min":  md5_min,
        "type":     ftype,
        "callees":  [hex(ea) for ea in sorted(callee_set)],
        "blocks":   blocks_raw,
        "strings":  strings,
        "consts":   constants,
        "call_tgts": call_targets,
    }


def _write_one(cur, data: dict, imp_cache: dict):
    """Write one function's collected data to the SQLite database.

    Must be called on a background thread (no IDAPython calls).
    """
    # Function row
    cur.execute("""
        INSERT OR REPLACE INTO functions
        (address, name, size, complexity, instructions,
         prototype, pseudocode, asm, bytes, md5, md5_min, type)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        data["ea"], data["name"], data["size"], data["complex"],
        data["asm_cnt"], data["proto"], data["pseudo"], data["asm"],
        data["bytes"], data["md5"], data["md5_min"], data["type"],
    ))

    # Basic blocks
    for b in (data.get("blocks") or []):
        try:
            cur.execute(
                "INSERT INTO basic_blocks VALUES (?, ?, ?)",
                (data["ea"], hex(b.start_ea), b.end_ea - b.start_ea),
            )
        except Exception:
            pass

    # Calls
    for callee_ea in data["callees"]:
        cur.execute("INSERT INTO calls VALUES (?, ?)", (data["ea"], callee_ea))

    # Strings
    for s in data["strings"]:
        cur.execute(
            "INSERT INTO strings VALUES (?, ?, ?)",
            (data["ea"], s["string"], s["xref"]),
        )

    # Constants
    for c in data["consts"]:
        cur.execute(
            "INSERT INTO constants VALUES (?, ?, ?)",
            (data["ea"], c["value"], c["op"]),
        )

    # Imports
    for ref in data.get("call_tgts") or []:
        imp = imp_cache.get(ref)
        if imp:
            cur.execute(
                "INSERT INTO imports VALUES (?, ?, ?)",
                (data["ea"], imp[0], imp[1]),
            )


# ---------------------------------------------------------------------------
# Diaphora export task management
# ---------------------------------------------------------------------------

EXPORT_TASKS: dict[str, dict] = {}
"""Holds export results keyed by task_id.  A missing key means 'in progress'."""


def _auto_decompiler(opts: dict) -> dict:
    """Auto-detect decompiler preference if not explicitly set.

    For databases with < 25 000 functions the decompiler is enabled by
    default to give richer pseudocode.  Larger databases keep it off to
    avoid the significant per-function cost of Hex-Rays decompilation.
    """
    if opts.get("use_decompiler") is not None:
        return opts  # Explicit agent preference, honour it

    try:
        import idautils
        total = len(list(idautils.Functions()))
        opts["use_decompiler"] = total < 25_000
    except Exception:
        opts["use_decompiler"] = False
    return opts


CONFIG_ACTION_ID = "mcp:configure"
CONFIG_ACTION_LABEL = "MCP Configuration"


class MCPConfigForm(idaapi.Form):
    """Form to configure MCP server host and port."""

    def __init__(self, host: str, port: int, autostart: bool, persist: bool):
        form_str = r"""STARTITEM 0
MCP Server Configuration

<Host:{host}>
<Port:{port}>
<Autostart server when IDA opens:{autostart}>
<Save host and port to this database:{save_endpoint}>{checks}>
"""
        super().__init__(
            form_str,
            {
                "host": idaapi.Form.StringInput(value=host),
                "port": idaapi.Form.NumericInput(value=port, tp=idaapi.Form.FT_DEC),
                "checks": idaapi.Form.ChkGroupControl(
                    ("autostart", "save_endpoint"),
                    value=(1 if autostart else 0) | (2 if persist else 0),
                ),
            },
        )


class MCPConfigHandler(idaapi.action_handler_t):
    def __init__(self, plugin: "MCP"):
        idaapi.action_handler_t.__init__(self)
        self.plugin = plugin

    def activate(self, ctx):
        old_host = self.plugin.host
        old_port = self.plugin.port
        old_autostart = self.plugin.autostart
        old_persist = self.plugin.persist_endpoint

        form = MCPConfigForm(
            self.plugin.host,
            self.plugin.port,
            self.plugin.autostart,
            self.plugin.persist_endpoint,
        )
        form.Compile()
        ok = form.Execute()
        if ok != 1:
            form.Free()
            return 0

        host = form.host.value
        port = form.port.value
        autostart = bool(form.checks.value & 1)
        persist = bool(form.checks.value & 2)
        form.Free()

        if port < 1 or port > 65535:
            print(f"[MCP] Invalid port: {port}")
            return 0

        if autostart != old_autostart:
            self.plugin.autostart = autostart
            _set_autostart(autostart)
            print(f"[MCP] Autostart {'enabled' if autostart else 'disabled'}")

        if persist != old_persist:
            self.plugin.persist_endpoint = persist
            _set_persist(persist)
            print(f"[MCP] Save host/port {'enabled' if persist else 'disabled'}")

        endpoint_changed = host != old_host or port != old_port
        self.plugin.host = host
        self.plugin.port = port

        # Save or forget the endpoint based on the preference.
        if persist:
            _set_host(host)
            _set_port(port)
            if endpoint_changed or persist != old_persist:
                print(f"[MCP] Configuration updated: {host}:{port} (saved to IDB)")
        else:
            if persist != old_persist:
                _clear_endpoint()  # next load falls back to defaults
            if endpoint_changed:
                print(f"[MCP] Configuration updated: {host}:{port} (not saved)")

        if not endpoint_changed and autostart == old_autostart and persist == old_persist:
            print(f"[MCP] Configuration unchanged: {host}:{port}")
            return 1

        # Apply new endpoint immediately if the server is running.
        if endpoint_changed and self.plugin.mcp is not None:
            print("[MCP] Applying configuration change without manual restart...")
            self.plugin.run(0)
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class MCPUIHooks(ida_kernwin.UI_Hooks):
    """Defers menu attachment and autostart until the UI is fully ready."""

    def __init__(self, plugin: "MCP"):
        super().__init__()
        self.plugin = plugin

    def ready_to_run(self):
        ida_kernwin.attach_action_to_menu(
            "Edit/Plugins/", CONFIG_ACTION_ID, idaapi.SETMENU_APP
        )
        # Skip autostart when running under idalib – the idalib_server manages
        # the MCP server lifecycle itself and would otherwise hit a port conflict
        # because unload_package creates a separate MCP_SERVER instance.
        if self.plugin.autostart and ida_kernwin.is_idaq():
            print("[MCP] Autostarting server...")
            self.plugin.run(0)
        self.unhook()


class MCP(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "MCP Plugin"
    help = "MCP"
    wanted_name = "MCP"
    wanted_hotkey = "Ctrl-Alt-M"

    DEFAULT_HOST = "127.0.0.1"
    DEFAULT_PORT = 13337

    def init(self):
        hotkey = MCP.wanted_hotkey.replace("-", "+")
        if __import__("sys").platform == "darwin":
            hotkey = hotkey.replace("Alt", "Option")

        self.mcp: "ida_mcp.rpc.McpServer | None" = None
        self.autostart = _get_autostart()
        self.persist_endpoint = _get_persist()
        if self.persist_endpoint:
            self.host = _get_host(self.DEFAULT_HOST)
            self.port = _get_port(self.DEFAULT_PORT)
        else:
            self.host = self.DEFAULT_HOST
            self.port = self.DEFAULT_PORT

        if self.autostart and ida_kernwin.is_idaq():
            print("[MCP] Plugin loaded, server will start automatically")
        elif not ida_kernwin.is_idaq():
            print("[MCP] Plugin loaded (idalib mode, server managed externally)")
        else:
            print(
                f"[MCP] Plugin loaded, use Edit -> Plugins -> MCP ({hotkey}) to start the server"
            )

        # Register a separate menu item for host/port configuration
        ida_kernwin.register_action(
            ida_kernwin.action_desc_t(
                CONFIG_ACTION_ID,
                CONFIG_ACTION_LABEL,
                MCPConfigHandler(self),
            )
        )
        # Defer menu attachment and autostart until the UI is fully initialized
        self._ui_hooks = MCPUIHooks(self)
        self._ui_hooks.hook()

        return idaapi.PLUGIN_KEEP

    def _unregister_instance(self):
        port = getattr(self, "_registered_port", None)
        if port is not None:
            try:
                if TYPE_CHECKING:
                    from .ida_mcp.discovery import unregister_instance
                else:
                    from ida_mcp.discovery import unregister_instance
                unregister_instance(port)
            except Exception as e:
                print(f"[MCP] Instance unregistration failed: {e}")
            self._registered_port = None

    def run(self, arg):
        if self.mcp:
            self._unregister_instance()
            self.mcp.stop()
            self.mcp = None

        # HACK: ensure fresh load of ida_mcp package
        unload_package("ida_mcp")
        if TYPE_CHECKING:
            from .ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler
        else:
            from ida_mcp import MCP_SERVER, IdaMcpHttpRequestHandler

        # ── Diaphora-aware request handler ──
        class _DiaphoraHandler(IdaMcpHttpRequestHandler):
            """Extends the MCP HTTP handler with Diaphora export endpoints.

            POST /diaphora/export       — starts an export task, returns task_id
            GET  /diaphora/export/<id>  — poll for task result
            GET  /diaphora/health       — health check
            """

            def do_GET(self):
                parsed = urlparse(self.path)
                path = parsed.path

                if path == "/diaphora/health":
                    return self._handle_diaphora_health()

                # Poll: GET /diaphora/export/<task_id>
                m = re.match(r"^/diaphora/export/([a-f0-9-]+)$", path)
                if m:
                    return self._handle_diaphora_poll(m.group(1))

                super().do_GET()

            def do_POST(self):
                parsed = urlparse(self.path)
                if parsed.path == "/diaphora/export":
                    return self._handle_diaphora_export()
                super().do_POST()

            def _send_json(self, data: dict, status: int = 200):
                body = json.dumps(data).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _handle_diaphora_health(self):
                import idc
                import idaapi
                def _get_path():
                    return idc.get_idb_path() if hasattr(idc, "get_idb_path") else ""
                path = idaapi.execute_sync(_get_path, idaapi.MFF_READ)
                self._send_json({
                    "ok": True,
                    "capabilities": ["diaphora/export"],
                    "idb_path": path,
                })

            def _handle_diaphora_export(self):
                if not self._check_api_request():
                    return

                # Read JSON body
                try:
                    length = int(self.headers.get("content-length", 0))
                    raw = self.rfile.read(length) if length > 0 else b"{}"
                    opts = json.loads(raw) if raw else {}
                except Exception as e:
                    self._send_json({"ok": False, "error": f"Invalid request: {e}"}, 400)
                    return

                state = {}
                def _sync_init():
                    state["output"] = opts.get("output_path") or (
                        os.path.splitext(idaapi.get_idb_path())[0] + ".diaphora.sqlite"
                    )
                    _auto_decompiler(opts)
                idaapi.execute_sync(_sync_init, idaapi.MFF_READ)
                output = state["output"]

                print(
                    f"[Diaphora] Export to {output} "
                    f"(decompiler={'on' if opts.get('use_decompiler') else 'off'})"
                )

                task_id = str(uuid.uuid4())

                def _worker():
                    """Run the export on a background thread.

                    _export_diaphora() now uses execute_sync() internally in
                    small batches (50 functions), so the main IDA thread is
                    never blocked for long.  No wrapping execute_sync needed.
                    """
                    progress = None
                    try:
                        if hasattr(idaapi, "timeldk_progress_t"):
                            progress = idaapi.timeldk_progress_t("Diaphora export")
                            progress.show()
                        path = _export_diaphora(output, opts, progress, task_id)
                        EXPORT_TASKS[task_id] = {"ok": True, "path": path}
                        print(f"[Diaphora] Export complete: {path}")
                    except RuntimeError as e:
                        err = str(e)
                        EXPORT_TASKS[task_id] = {"ok": False, "error": err}
                        print(f"[Diaphora] Export {'cancelled' if err == 'cancelled' else 'failed'}: {err}")
                    except Exception as e:
                        EXPORT_TASKS[task_id] = {"ok": False, "error": str(e)}
                        print(f"[Diaphora] Export failed: {e}")
                    finally:
                        if progress:
                            def _close_progress():
                                try:
                                    progress.close()
                                except Exception:
                                    pass
                            idaapi.execute_sync(_close_progress, idaapi.MFF_WRITE)

                threading.Thread(target=_worker, daemon=True).start()
                self._send_json({"ok": True, "task_id": task_id})

            def _handle_diaphora_poll(self, task_id: str):
                if task_id not in EXPORT_TASKS:
                    self._send_json({"done": False, "percentage": 0})
                    return

                result = dict(EXPORT_TASKS[task_id])
                if "ok" in result:
                    result["done"] = True
                else:
                    result["done"] = False
                self._send_json(result)

        port = self.port
        max_port = port + 100
        while port < max_port:
            try:
                MCP_SERVER.serve(
                    self.host, port, request_handler=_DiaphoraHandler
                )
                print(f"  Config: http://{self.host}:{port}/config.html")
                print(f"  Diaphora: http://{self.host}:{port}/diaphora/health")
                self.mcp = MCP_SERVER
                self._register_instance(port)
                return
            except OSError as e:
                if e.errno in (48, 98, 10048):  # Address already in use
                    port += 1
                else:
                    raise
        print(f"[MCP] Error: No available port in range {self.port}-{max_port - 1}")

    def _register_instance(self, port: int):
        try:
            if TYPE_CHECKING:
                from .ida_mcp.discovery import register_instance
            else:
                from ida_mcp.discovery import register_instance
            import os
            import idc
            import ida_nalt
            binary = ida_nalt.get_root_filename() or ""
            idb_path = idc.get_idb_path() or ""
            file_path = register_instance(
                host=self.host,
                port=port,
                pid=os.getpid(),
                binary=binary,
                idb_path=idb_path,
            )
            self._registered_port = port
            print(f"[MCP] Registered instance: {binary} (pid={os.getpid()}, port={port})")
            print(f"  Discovery file: {file_path}")
        except Exception as e:
            import traceback
            print(f"[MCP] Instance registration failed: {e}")
            traceback.print_exc()

    def term(self):
        if hasattr(self, "_ui_hooks"):
            self._ui_hooks.unhook()
        ida_kernwin.unregister_action(CONFIG_ACTION_ID)
        self._unregister_instance()
        if self.mcp:
            self.mcp.stop()


def PLUGIN_ENTRY():
    return MCP()


