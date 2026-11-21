"""
PS4DeepMCP — Sovereign Deep-Access MCP Server for PS4 Pro (FW 13.02 · GoldHEN + ps4debug-NG).
Exposes 38 low-level tools for live memory inspection, kernel R/W, RPC calls, ELF injection,
root FTP filesystem & Orbis SQLite DB access, LAN decrypted game dumping, Mini-IDA x86-64
reverse engineering (Capstone + RIP-relative string xrefs + function decompiler summary),
animated wallpaper / ATRAC9 theme building, and offline-cached 13.02 exploit hosting.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

from exploit_host import ExploitHostServer
from goldhen_bridge import GoldHENBridge
from orbis_re import (
    binary_diff_files,
    decompile_function_summary,
    disassemble_bytes,
    disassemble_elf_at,
    discover_functions,
    extract_strings_and_xrefs,
    generate_goldhen_patch_json,
    parse_param_sfo,
    parse_self_or_elf,
)
from ps4_config import ROOT_DIR, get_dir, load_config, update_nested_config
from ps4debug_client import PS4DebugClient
from theme_studio import (
    build_dynamic_theme_workspace,
    convert_audio_to_ps4_at9,
    prepare_wallpaper_image,
)

mcp = FastMCP("ps4-deep-mcp")

_cfg = load_config()
_dbg = PS4DebugClient(
    host=_cfg["target"]["ip"],
    port=int(_cfg["ports"]["ps4debug"]),
    timeout=float(_cfg["target"].get("timeout_sec", 8.0)),
)
_bridge = GoldHENBridge(_cfg, ROOT_DIR)
_exploit_host = ExploitHostServer(
    exploit_dir=get_dir(_cfg, "exploit_files_dir"),
    port=int(_cfg["ports"].get("local_exploit_host", 8088)),
    target_ip=_cfg["target"]["ip"],
)


def _reload_clients() -> dict[str, Any]:
    global _cfg, _dbg, _bridge, _exploit_host
    _cfg = load_config()
    _dbg = PS4DebugClient(
        host=_cfg["target"]["ip"],
        port=int(_cfg["ports"]["ps4debug"]),
        timeout=float(_cfg["target"].get("timeout_sec", 8.0)),
    )
    _bridge.cfg = _cfg
    _exploit_host.target_ip = _cfg["target"]["ip"]
    _exploit_host.port = int(_cfg["ports"].get("local_exploit_host", 8088))
    return _cfg


def _parse_int(val: str | int) -> int:
    if isinstance(val, int):
        return val
    return int(str(val).strip(), 0)


def _ok(data: Any) -> str:
    return json.dumps({"ok": True, "data": data}, indent=2)


# =============================================================================
# 1. CONFIGURATION & TARGET PROBES
# =============================================================================
@mcp.tool()
def ps4_get_config() -> str:
    """Return current PS4 target configuration, ports, kernel offset slots, and tool paths."""
    return _ok(load_config())


@mcp.tool()
def ps4_set_config(dot_path: str, value: Any) -> str:
    """
    Update any named config entry in config.json (e.g. 'target.ip', 'target.user_id',
    'kernel_offsets.allproc_offset', 'external_tools.at9tool').
    """
    updated = update_nested_config(dot_path, value)
    _reload_clients()
    return _ok({"updated": dot_path, "value": value, "config": updated})


@mcp.tool()
def ps4_probe_services() -> str:
    """Probe all PS4 GoldHEN & ps4debug-NG LAN ports (744, 2121, 9090, 12800, 3232)."""
    _reload_clients()
    return _ok(_bridge.probe_services())


@mcp.tool()
def ps4_version_and_notify(message: str = "PS4DeepMCP Connected") -> str:
    """Check ps4debug-NG version and display an on-screen notification toast on the PS4."""
    ver = _dbg.version()
    _dbg.notify(message)
    return _ok({"ps4debug_version": ver, "notified": message})


@mcp.tool()
def ps4_console_info() -> str:
    """Query hardware/console info from ps4debug-NG."""
    return _ok(_dbg.console_info())


# =============================================================================
# 2. LIVE PROCESS, MEMORY, AOB SCANNER, PATCHING, RPC & KERNEL (ps4debug-NG)
# =============================================================================
@mcp.tool()
def ps4_proc_list() -> str:
    """List every running OrbisOS process (SceShellUI, running games, system daemons) with PIDs."""
    procs = _dbg.process_list()
    return _ok([{"pid": p.pid, "name": p.name} for p in procs])


@mcp.tool()
def ps4_proc_info(pid: int) -> str:
    """Retrieve Title ID, Content ID, executable path, and process name for a running PS4 PID."""
    return _ok(_dbg.process_info(pid))


@mcp.tool()
def ps4_proc_maps(pid: int, name_filter: str = "") -> str:
    """List virtual memory mappings (eboot.bin, .sprx libraries, heap, stack) with R/W/X permissions."""
    maps = _dbg.process_maps(pid)
    if name_filter:
        maps = [m for m in maps if name_filter.lower() in m.name.lower()]
    return _ok([m.to_dict() for m in maps])


@mcp.tool()
def ps4_mem_read(pid: int, address: str, length: int = 64, disassemble: bool = False) -> str:
    """Read live RAM bytes from a running PS4 process (hex + ASCII + optional Capstone x86-64 disasm)."""
    addr = _parse_int(address)
    raw = _dbg.read_memory(pid, addr, length)
    out: dict[str, Any] = {
        "pid": pid,
        "address": hex(addr),
        "length": len(raw),
        "hex": raw.hex(),
        "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in raw),
    }
    if disassemble:
        out["disassembly"] = disassemble_bytes(raw, addr, max_instructions=64)
    return _ok(out)


@mcp.tool()
def ps4_mem_write_safe(pid: int, address: str, hex_bytes: str) -> str:
    """
    Safely write bytes to PS4 process memory with automatic LIFO RWX protection lift/restore
    and reversible undo ledger recording.
    """
    addr = _parse_int(address)
    data = bytes.fromhex(hex_bytes.replace(" ", ""))
    return _ok(_dbg.patch_bytes_safe(pid, addr, data))


@mcp.tool()
def ps4_mem_revert_last_patch() -> str:
    """Revert the most recent reversible live memory patch recorded in the patch ledger."""
    return _ok(_dbg.revert_last_patch())


@mcp.tool()
def ps4_aob_scan(
    pid: int,
    pattern: str,
    module_filter: str = "",
    executable_only: bool = True,
    max_results: int = 25,
) -> str:
    """Scan live PS4 process RAM for an IDA-style wildcard byte pattern (e.g. '48 8B 05 ?? ?? ?? ??')."""
    hits = _dbg.aob_scan(
        pid=pid,
        pattern=pattern,
        module_filter=module_filter or None,
        executable_only=executable_only,
        max_results=max_results,
    )
    return _ok({"pid": pid, "pattern": pattern, "hit_count": len(hits), "hits": hits})


@mcp.tool()
def ps4_pointer_chain(pid: int, base_address: str, offsets: list[str]) -> str:
    """Follow a multi-level 64-bit pointer chain in live PS4 process memory."""
    base = _parse_int(base_address)
    offs = [_parse_int(o) for o in offsets]
    return _ok(_dbg.resolve_pointer_chain(pid, base, offs))


@mcp.tool()
def ps4_proc_alloc(pid: int, size: int) -> str:
    """Allocate a memory region inside a target PS4 process (returns allocated address)."""
    addr = _dbg.allocate_memory(pid, size)
    return _ok({"pid": pid, "address": hex(addr), "size": size})


@mcp.tool()
def ps4_proc_free(pid: int, address: str, size: int) -> str:
    """Free a previously allocated memory region inside a target PS4 process."""
    addr = _parse_int(address)
    _dbg.free_memory(pid, addr, size)
    return _ok({"pid": pid, "freed": hex(addr), "size": size})


@mcp.tool()
def ps4_proc_rpc_call(pid: int, function_address: str, args: list[str] | None = None, rpc_stub: str = "") -> str:
    """Install (if needed) the ps4debug-NG RPC stub and execute a function inside a PS4 process."""
    stub = _parse_int(rpc_stub) if rpc_stub else _dbg.install_rpc(pid)
    fn_addr = _parse_int(function_address)
    int_args = [_parse_int(a) for a in (args or [])]
    rax = _dbg.call_function(pid, stub, fn_addr, int_args)
    return _ok({"pid": pid, "rpc_stub": hex(stub), "function": hex(fn_addr), "return_rax": hex(rax)})


@mcp.tool()
def ps4_proc_inject_elf(pid: int, local_elf_path: str) -> str:
    """Inject a compiled Orbis ELF payload directly into a running PS4 process."""
    p = Path(local_elf_path)
    entry = _dbg.inject_elf(pid, p.read_bytes())
    return _ok({"pid": pid, "elf": str(p), "entry_point": hex(entry)})


@mcp.tool()
def ps4_kern_base() -> str:
    """Read the live OrbisOS kernel base virtual address from ps4debug-NG."""
    override = load_config().get("kernel_offsets", {}).get("kernel_base_override")
    if override:
        return _ok({"kernel_base": hex(_parse_int(override)), "source": "config_override"})
    base = _dbg.kernel_base()
    return _ok({"kernel_base": hex(base), "source": "ps4debug_live"})


@mcp.tool()
def ps4_kern_read(address: str, length: int = 64) -> str:
    """Read raw kernel virtual memory bytes from OrbisOS."""
    addr = _parse_int(address)
    raw = _dbg.kernel_read(addr, length)
    return _ok({"address": hex(addr), "length": len(raw), "hex": raw.hex()})


@mcp.tool()
def ps4_kern_write(address: str, hex_bytes: str) -> str:
    """Write raw bytes to OrbisOS kernel memory (use with exact verified 13.02 offsets)."""
    addr = _parse_int(address)
    data = bytes.fromhex(hex_bytes.replace(" ", ""))
    _dbg.kernel_write(addr, data)
    return _ok({"address": hex(addr), "bytes_written": len(data)})


@mcp.tool()
def ps4_debug_threads_and_regs(pid: int, attach_first: bool = True) -> str:
    """Attach debugger to PID, list all LWP thread IDs, and read x86-64 registers of the main thread."""
    if attach_first:
        _dbg.debug_attach(pid)
    threads = _dbg.debug_threads()
    regs = _dbg.debug_get_regs(threads[0]) if threads else {}
    return _ok({"pid": pid, "threads": threads, "primary_thread_regs": regs})


@mcp.tool()
def ps4_debug_detach() -> str:
    """Cleanly detach the ps4debug-NG hardware debugger from the attached process."""
    _dbg.debug_detach()
    return _ok({"detached": True})


# =============================================================================
# 3. GOLDHEN ROOT FILESYSTEM, ORBIS SQLITE DB, PAYLOADS, KLOG & PKG INSTALL
# =============================================================================
@mcp.tool()
def ps4_fs_ls(remote_path: str = "/") -> str:
    """List files and directories anywhere on the PS4 root filesystem via GoldHEN FTP."""
    return _ok(_bridge.fs_list(remote_path))


@mcp.tool()
def ps4_fs_pull(remote_path: str, local_filename: str = "") -> str:
    """Download any file from the PS4 to the local dumps directory via GoldHEN FTP."""
    dumps = get_dir(_cfg, "dumps_dir")
    name = local_filename or Path(remote_path).name
    return _ok(_bridge.fs_pull(remote_path, dumps / name))


@mcp.tool()
def ps4_fs_push(local_path: str, remote_path: str) -> str:
    """Upload a local file to any writable path on the PS4 via GoldHEN FTP."""
    return _ok(_bridge.fs_push(Path(local_path), remote_path))


@mcp.tool()
def ps4_db_query(remote_db_path: str, sql: str, write_back: bool = False) -> str:
    """
    Pull an Orbis SQLite database (e.g. /system_data/priv/mms/app.db or addcont.db),
    create an automatic timestamped backup, run SQL, and optionally push back safely.
    """
    return _ok(
        _bridge.query_orbis_db(
            remote_db_path=remote_db_path,
            sql=sql,
            write_back=write_back,
            backups_dir=get_dir(_cfg, "backups_dir"),
        )
    )


@mcp.tool()
def ps4_send_payload(local_payload_path: str) -> str:
    """Inject a .bin or .elf payload into GoldHEN BinLoader (port 9090)."""
    return _ok(_bridge.send_payload(Path(local_payload_path)))


@mcp.tool()
def ps4_read_klog(duration_sec: float = 2.5) -> str:
    """Capture live OrbisOS kernel log (klog) output from GoldHEN port 3232."""
    return _ok(_bridge.read_klog(duration_sec=duration_sec))


@mcp.tool()
def ps4_install_pkg_lan(local_pkg_path: str) -> str:
    """Serve a local .pkg file over LAN HTTP and trigger Remote PKG Installer (port 12800)."""
    return _ok(_bridge.install_pkg_over_lan(Path(local_pkg_path)))


# =============================================================================
# 4. LIVE GAME DUMPING & MINI-IDA REVERSE ENGINEERING SUITE
# =============================================================================
@mcp.tool()
def ps4_dump_live_module_elf(pid: int, module_name: str = "eboot.bin", output_name: str = "") -> str:
    """
    Extract decrypted executable & data segments of a running PS4 module (eboot.bin or .sprx)
    directly from live RAM via ps4debug-NG and reconstruct a clean x86-64 ELF64 binary on PC.
    """
    dumps = get_dir(_cfg, "dumps_dir")
    out_file = dumps / (output_name or f"pid{pid}_{module_name}.elf")
    return _ok(_dbg.dump_live_module_to_elf(pid, module_name, out_file))


@mcp.tool()
def ps4_dump_running_game_assets(title_id: str, max_files: int = 300, max_total_mb: int = 1024) -> str:
    """
    Mirror decrypted mounted PFS game assets (/mnt/sandbox/pfsmnt/<TITLEID>-app0-app0-nest)
    straight to PC SSD over gigabit LAN without needing a USB drive.
    """
    dumps = get_dir(_cfg, "dumps_dir") / title_id
    remote_mount = f"/mnt/sandbox/pfsmnt/{title_id}-app0-app0-nest"
    return _ok(_bridge.fs_mirror_dir(remote_mount, dumps, max_files=max_files, max_total_mb=max_total_mb))


@mcp.tool()
def re_inspect_self_or_elf(local_binary_path: str) -> str:
    """Parse PS4 SELF (0x1D3D154F) headers, encryption flags, or Orbis ELF64 program segments."""
    return _ok(parse_self_or_elf(Path(local_binary_path)))


@mcp.tool()
def re_parse_param_sfo(local_sfo_path: str) -> str:
    """Parse a PS4 param.sfo file to inspect TITLE_ID, APP_VER, VERSION, CONTENT_ID, and metadata."""
    return _ok(parse_param_sfo(Path(local_sfo_path)))


@mcp.tool()
def re_disassemble_elf(local_elf_path: str, vaddr: str, byte_length: int = 256, max_instructions: int = 120) -> str:
    """Disassemble x86-64 Orbis ELF code with Capstone 5 + automatic RIP-relative string annotation."""
    return _ok(disassemble_elf_at(Path(local_elf_path), _parse_int(vaddr), byte_length, max_instructions))


@mcp.tool()
def re_discover_functions(local_elf_path: str, limit: int = 200) -> str:
    """Scan executable segments of a dumped Orbis ELF to recover x86-64 function entry points."""
    return _ok(discover_functions(Path(local_elf_path), limit=limit))


@mcp.tool()
def re_find_string_xrefs(local_elf_path: str, search_text: str, max_matches: int = 30) -> str:
    """
    IDA-style String Xref Analyzer: locate matching ASCII strings in a decrypted Orbis ELF
    and find every x86-64 `lea`/`mov [rip+disp]` instruction referencing them.
    """
    return _ok(extract_strings_and_xrefs(Path(local_elf_path), search_text, max_matches=max_matches))


@mcp.tool()
def re_decompile_function(local_elf_path: str, func_vaddr: str, max_bytes: int = 1024) -> str:
    """Mini-IDA function analysis: stack frame size, call graph, branches, string refs, and annotated disasm."""
    return _ok(decompile_function_summary(Path(local_elf_path), _parse_int(func_vaddr), max_bytes=max_bytes))


@mcp.tool()
def re_binary_diff(file_a: str, file_b: str, max_diffs: int = 64) -> str:
    """Diff two binary files/dumps byte-for-byte to locate patch offsets."""
    return _ok(binary_diff_files(Path(file_a), Path(file_b), max_diffs=max_diffs))


@mcp.tool()
def re_export_goldhen_patch(
    title: str,
    title_id: str,
    app_ver: str,
    patch_name: str,
    patch_entries: list[dict[str, str]],
    push_to_ps4: bool = False,
) -> str:
    """
    Export a GoldHEN .json patch file (and optionally upload straight to /data/GoldHEN/patches/json/).
    Each entry in patch_entries: {"offset": "0x1234", "on": "909090", "off": "8945fc"}.
    """
    pdir = get_dir(_cfg, "patches_dir")
    out_file = pdir / f"{title_id}.json"
    res = generate_goldhen_patch_json(title, title_id, app_ver, patch_name, "PS4DeepMCP", patch_entries, out_file)
    if push_to_ps4:
        res["ftp_upload"] = _bridge.fs_push(out_file, res["remote_goldhen_path"])
    return _ok(res)


# =============================================================================
# 5. ANIMATED WALLPAPER, DYNAMIC THEME & ATRAC9 AUDIO STUDIO
# =============================================================================
@mcp.tool()
def ps4_deploy_wallpaper(local_image_path: str, wallpaper_name: str = "sovereign_bg") -> str:
    """
    Resize any image to exact PS4 Pro 1920x1080 wallpaper spec, push to /user/home/<user_id>/wallpaper/
    over GoldHEN FTP, and notify the PS4 screen.
    """
    cfg = load_config()
    uid = cfg["target"]["user_id"]
    tdir = get_dir(cfg, "themes_dir") / "wallpapers"
    prep = prepare_wallpaper_image(Path(local_image_path), tdir, name=wallpaper_name)
    remote_path = f"/user/home/{uid}/wallpaper/{wallpaper_name}.jpg"
    upload = _bridge.fs_push(Path(prep["wallpaper_jpg"]), remote_path)
    try:
        _dbg.notify(f"Wallpaper installed: {wallpaper_name}")
    except Exception:
        pass
    return _ok({"prepared": prep, "uploaded": upload})


@mcp.tool()
def ps4_build_animated_theme(
    theme_name: str,
    local_visual_path: str,
    local_audio_path: str = "",
    accent_color_hex: str = "1ED760",
) -> str:
    """
    Build a complete PS4 Dynamic Theme workspace from an animated GIF/WebP/MP4 + MP3/WAV audio:
    extracts 1920x1080 frames, builds theme.xml, and prepares 48kHz WAV / bgm_home.at9 audio.
    """
    cfg = load_config()
    themes_root = get_dir(cfg, "themes_dir")
    audio_p = Path(local_audio_path) if local_audio_path else None
    return _ok(
        build_dynamic_theme_workspace(
            theme_name=theme_name,
            visual_source=Path(local_visual_path),
            audio_source=audio_p,
            themes_root=themes_root,
            cfg=cfg,
            primary_color_hex=accent_color_hex,
        )
    )


@mcp.tool()
def ps4_convert_bgm_audio(local_audio_path: str, bitrate_kbps: int = 144, loop: bool = True) -> str:
    """Convert any MP3/WAV/OGG audio to PS4 48kHz stereo WAV / ATRAC9 (.at9) background music."""
    cfg = load_config()
    out_dir = get_dir(cfg, "themes_dir") / "audio"
    return _ok(convert_audio_to_ps4_at9(Path(local_audio_path), out_dir, cfg, bitrate_kbps=bitrate_kbps, loop=loop))


# =============================================================================
# 6. SELF-HOSTED OFFLINE 13.02 EXPLOIT HUB & AUTO-REBOOT PAYLOAD WATCHER
# =============================================================================
@mcp.tool()
def ps4_exploit_host_start() -> str:
    """
    Start the local HTML5 AppCache offline-cached 13.02 browser exploit & payload host on LAN.
    Visit the returned URL once from your PS4 Pro browser to cache it offline across reboots.
    """
    _reload_clients()
    return _ok(_exploit_host.start())


@mcp.tool()
def ps4_exploit_host_stop() -> str:
    """Stop the local offline-cached exploit host HTTP server."""
    return _ok(_exploit_host.stop())


@mcp.tool()
def ps4_auto_watcher_start(payload_paths: list[str] | None = None, poll_interval_sec: float = 4.0) -> str:
    """
    Start the background LAN watcher: the instant GoldHEN BinLoader (9090) comes online after a reboot
    and ps4debug-NG (744) is offline, automatically injects your startup payloads (e.g. ps4debug-NG).
    """
    cfg = load_config()
    paths = payload_paths if payload_paths is not None else cfg.get("auto_watcher", {}).get("startup_payloads", [])
    return _ok(_bridge.start_auto_watcher(paths, poll_sec=poll_interval_sec))


@mcp.tool()
def ps4_auto_watcher_status() -> str:
    """Check status and injection history of the background GoldHEN auto-payload watcher."""
    return _ok(_bridge.watcher_status())


if __name__ == "__main__":
    mcp.run(transport="stdio")
