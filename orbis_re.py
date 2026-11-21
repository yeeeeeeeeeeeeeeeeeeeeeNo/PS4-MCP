"""
Orbis Reverse-Engineering Engine ("Mini-IDA Pro" in Pure Python + Capstone 5):
- PS4 SELF (0x1D3D154F) & ELF64 Orbis header / segment / dynamic / NID inspector
- PS4 param.sfo (\x00PSF) parser
- x86-64 Disassembler with RIP-relative string & call-target annotation
- Automated Function Discovery (prologues + call targets)
- Real IDA-Style String Xref Engine (scans executable segments for `lea reg, [rip+disp]` -> string)
- Function Control-Flow & Pseudo-Decompilation Summary
- GoldHEN .json / .mc4 Cheat & Binary Patch Generator
- Binary Diff Engine
"""

from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from capstone import CS_ARCH_X86, CS_MODE_64, Cs

SELF_MAGIC = 0x1D3D154F
ELF_MAGIC = b"\x7fELF"
SFO_MAGIC = b"\x00PSF"

PT_NAMES = {
    0: "PT_NULL",
    1: "PT_LOAD",
    2: "PT_DYNAMIC",
    3: "PT_INTERP",
    4: "PT_NOTE",
    6: "PT_PHDR",
    7: "PT_TLS",
    0x60000000: "PT_SCE_RELA",
    0x61000000: "PT_SCE_DYNLIBDATA",
    0x61000001: "PT_SCE_PROCPARAM",
    0x61000002: "PT_SCE_MODULE_PARAM",
    0x61000010: "PT_SCE_RELRO",
    0x6474E550: "PT_GNU_EH_FRAME",
    0x6474E551: "PT_GNU_STACK",
    0x6FFFFF00: "PT_SCE_COMMENT",
    0x6FFFFF01: "PT_SCE_LIBVERSION",
}


@dataclass
class ElfSegment:
    p_type: int
    p_flags: int
    p_offset: int
    p_vaddr: int
    p_filesz: int
    p_memsz: int

    @property
    def type_name(self) -> str:
        return PT_NAMES.get(self.p_type, hex(self.p_type))

    @property
    def is_exec(self) -> bool:
        return bool(self.p_flags & 1)

    @property
    def is_write(self) -> bool:
        return bool(self.p_flags & 2)

    @property
    def is_read(self) -> bool:
        return bool(self.p_flags & 4)

    @property
    def perm_str(self) -> str:
        return ("r" if self.is_read else "-") + ("w" if self.is_write else "-") + ("x" if self.is_exec else "-")


def parse_param_sfo(path: Path) -> dict[str, Any]:
    """Parses Sony PS4 param.sfo binary metadata tables."""
    data = path.read_bytes()
    if len(data) < 20 or data[:4] != SFO_MAGIC:
        raise ValueError("Not a valid Sony PSF/param.sfo file")
    _, version, key_table_off, data_table_off, entry_count = struct.unpack("<4sIIII", data[:20])
    entries: dict[str, Any] = {}
    for i in range(entry_count):
        base = 20 + i * 16
        k_off, d_fmt, d_len, d_max, d_off = struct.unpack("<HHIII", data[base : base + 16])
        k_start = key_table_off + k_off
        k_end = data.find(b"\x00", k_start)
        key = data[k_start:k_end].decode("utf-8", errors="replace")
        v_start = data_table_off + d_off
        raw_val = data[v_start : v_start + d_len]
        if d_fmt == 0x0404 and len(raw_val) >= 4:
            val: Any = struct.unpack("<I", raw_val[:4])[0]
        else:
            val = raw_val.rstrip(b"\x00").decode("utf-8", errors="replace")
        entries[key] = val
    return {"version": hex(version), "entry_count": entry_count, "fields": entries}


def parse_self_or_elf(path: Path) -> dict[str, Any]:
    """Inspects a PS4 SELF (signed/encrypted) or decrypted Orbis ELF64 binary."""
    data = path.read_bytes()
    if len(data) < 64:
        raise ValueError("File too small to be SELF or ELF64")

    (magic32,) = struct.unpack("<I", data[:4])
    result: dict[str, Any] = {"file": str(path), "size": len(data)}

    if magic32 == SELF_MAGIC:
        result["format"] = "PS4_SELF"
        version, mode, endian, attr = struct.unpack("<BBBB", data[4:8])
        key_type, header_size, meta_size, file_size, entry_count, flags = struct.unpack("<IHHIHH", data[8:26])
        self_segs = []
        off = 32
        for i in range(entry_count):
            if off + 32 > len(data):
                break
            s_flags, s_off, s_comp_sz, s_uncomp_sz = struct.unpack("<QQQQ", data[off : off + 32])
            self_segs.append(
                {
                    "index": i,
                    "flags": hex(s_flags),
                    "encrypted": bool(s_flags & 0x2),
                    "signed": bool(s_flags & 0x4),
                    "deflated": bool(s_flags & 0x8),
                    "blocked": bool(s_flags & 0x800),
                    "offset": hex(s_off),
                    "compressed_size": s_comp_sz,
                    "uncompressed_size": s_uncomp_sz,
                }
            )
            off += 32
        result["self_header"] = {
            "header_size": header_size,
            "meta_size": meta_size,
            "entry_count": entry_count,
            "flags": hex(flags),
            "segments": self_segs,
        }
        # Locate embedded ELF header inside SELF
        elf_pos = data.find(ELF_MAGIC, off)
        if elf_pos != -1:
            result["embedded_elf_offset"] = hex(elf_pos)
            result["elf"] = _parse_elf64_bytes(data[elf_pos:])
        else:
            result["note"] = "SELF segments are encrypted on disk; use ps4_dump_live_module to extract decrypted ELF directly from running PS4 RAM."
        return result

    if data[:4] == ELF_MAGIC:
        result["format"] = "ORBIS_ELF64"
        result["elf"] = _parse_elf64_bytes(data)
        return result

    raise ValueError(f"Unrecognized binary magic: {data[:4].hex()}")


def _parse_elf64_bytes(data: bytes) -> dict[str, Any]:
    if len(data) < 64 or data[:4] != ELF_MAGIC or data[4] != 2:
        raise ValueError("Not a valid 64-bit ELF")
    e_type, e_machine, _, e_entry, e_phoff, e_shoff, _, _, e_phentsize, e_phnum, _, e_shnum, _ = struct.unpack(
        "<HHIQQQIHHHHHH", data[16:64]
    )
    segs: list[dict[str, Any]] = []
    for i in range(e_phnum):
        pos = e_phoff + i * e_phentsize
        if pos + 56 > len(data):
            break
        p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, p_align = struct.unpack(
            "<IIQQQQQQ", data[pos : pos + 56]
        )
        seg = ElfSegment(p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz)
        segs.append(
            {
                "index": i,
                "type": seg.type_name,
                "perms": seg.perm_str,
                "offset": hex(seg.p_offset),
                "vaddr": hex(seg.p_vaddr),
                "filesz": seg.p_filesz,
                "memsz": seg.p_memsz,
            }
        )
    return {
        "e_type": hex(e_type),
        "e_machine": "x86_64" if e_machine == 62 else hex(e_machine),
        "entry_point": hex(e_entry),
        "phnum": e_phnum,
        "shnum": e_shnum,
        "segments": segs,
    }


def _load_elf_segments(data: bytes) -> list[ElfSegment]:
    if len(data) < 64 or data[:4] != ELF_MAGIC:
        return []
    _, _, _, _, e_phoff, _, _, _, e_phentsize, e_phnum, _, _, _ = struct.unpack("<HHIQQQIHHHHHH", data[16:64])
    out: list[ElfSegment] = []
    for i in range(e_phnum):
        pos = e_phoff + i * e_phentsize
        if pos + 56 > len(data):
            break
        p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack("<IIQQQQQQ", data[pos : pos + 56])
        if p_type == 1 and p_filesz > 0:
            out.append(ElfSegment(p_type, p_flags, p_offset, p_vaddr, p_filesz, p_memsz))
    return out


def vaddr_to_offset(segs: list[ElfSegment], vaddr: int) -> int | None:
    for s in segs:
        if s.p_vaddr <= vaddr < s.p_vaddr + s.p_filesz:
            return s.p_offset + (vaddr - s.p_vaddr)
    return None


def _read_cstr_at_vaddr(data: bytes, segs: list[ElfSegment], vaddr: int, max_len: int = 96) -> str | None:
    off = vaddr_to_offset(segs, vaddr)
    if off is None or off >= len(data):
        return None
    end = data.find(b"\x00", off, min(len(data), off + max_len))
    if end == -1 or end - off < 3:
        return None
    raw = data[off:end]
    if all(32 <= b < 127 for b in raw):
        return raw.decode("ascii")
    return None


# =============================================================================
# X86-64 DISASSEMBLER + RIP-RELATIVE ANNOTATOR (CAPSTONE 5)
# =============================================================================
def disassemble_bytes(
    code: bytes,
    base_vaddr: int,
    max_instructions: int = 120,
    full_elf_data: bytes | None = None,
    elf_segs: list[ElfSegment] | None = None,
) -> list[dict[str, Any]]:
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = False
    out: list[dict[str, Any]] = []
    rip_re = re.compile(r"\[rip\s*([+-])\s*0x([0-9a-fA-F]+)\]")

    for idx, ins in enumerate(md.disasm(code, base_vaddr)):
        if idx >= max_instructions:
            break
        comment = ""
        m = rip_re.search(ins.op_str)
        if m:
            sign = 1 if m.group(1) == "+" else -1
            disp = int(m.group(2), 16)
            target = ins.address + ins.size + sign * disp
            comment = f"target={hex(target)}"
            if full_elf_data and elf_segs:
                s = _read_cstr_at_vaddr(full_elf_data, elf_segs, target)
                if s:
                    comment += f' "{s}"'
        out.append(
            {
                "address": hex(ins.address),
                "bytes": ins.bytes.hex(),
                "mnemonic": ins.mnemonic,
                "op_str": ins.op_str,
                "comment": comment,
            }
        )
    return out


def disassemble_elf_at(path: Path, vaddr: int, byte_length: int = 256, max_instructions: int = 120) -> dict[str, Any]:
    data = path.read_bytes()
    segs = _load_elf_segments(data)
    off = vaddr_to_offset(segs, vaddr)
    if off is None:
        # Fallback: treat vaddr as raw file offset if not mapped
        off = vaddr
    chunk = data[off : off + byte_length]
    insns = disassemble_bytes(chunk, vaddr, max_instructions=max_instructions, full_elf_data=data, elf_segs=segs)
    return {"file": str(path), "vaddr": hex(vaddr), "count": len(insns), "instructions": insns}


# =============================================================================
# AUTOMATED FUNCTION RECOVERY & MINI-IDA DECOMPILER SUMMARY
# =============================================================================
def discover_functions(path: Path, limit: int = 200) -> dict[str, Any]:
    """Discovers x86-64 function entry points via prologue signatures & call targets."""
    data = path.read_bytes()
    segs = _load_elf_segments(data)
    exec_segs = [s for s in segs if s.is_exec]
    funcs: dict[int, str] = {}

    prologue_patterns = [
        (b"\x55\x48\x89\xe5", "push rbp; mov rbp, rsp"),
        (b"\xf3\x0f\x1e\xfa\x55\x48\x89\xe5", "endbr64; push rbp; mov rbp, rsp"),
        (b"\x41\x57\x41\x56\x41\x55", "callee-saved prologue"),
    ]

    for seg in exec_segs:
        blob = data[seg.p_offset : seg.p_offset + seg.p_filesz]
        for pat, tag in prologue_patterns:
            pos = 0
            while len(funcs) < limit:
                hit = blob.find(pat, pos)
                if hit == -1:
                    break
                # Require alignment or previous int3/nop/ret byte to avoid mid-instruction false hits
                if hit == 0 or (hit % 16 == 0) or blob[hit - 1] in (0xCC, 0x90, 0xC3):
                    funcs.setdefault(seg.p_vaddr + hit, tag)
                pos = hit + 1

    ordered = [{"address": hex(a), "signature": funcs[a]} for a in sorted(funcs.keys())[:limit]]
    return {"file": str(path), "executable_segments": len(exec_segs), "functions_found": len(ordered), "functions": ordered}


def extract_strings_and_xrefs(
    path: Path,
    search_substring: str,
    max_matches: int = 30,
) -> dict[str, Any]:
    """
    Finds ASCII strings matching `search_substring` in a decrypted Orbis ELF
    and scans executable segments for RIP-relative `lea`/`mov` instructions referencing them!
    """
    data = path.read_bytes()
    segs = _load_elf_segments(data)
    query_b = search_substring.encode("ascii", errors="ignore").lower()
    str_hits: list[dict[str, Any]] = []
    target_vaddrs: dict[int, str] = {}

    ascii_re = re.compile(rb"[\x20-\x7e]{4,160}")
    for seg in segs:
        blob = data[seg.p_offset : seg.p_offset + seg.p_filesz]
        for m in ascii_re.finditer(blob):
            if query_b in m.group(0).lower():
                va = seg.p_vaddr + m.start()
                s_val = m.group(0).decode("ascii", errors="ignore")
                target_vaddrs[va] = s_val
                str_hits.append({"vaddr": hex(va), "segment": seg.perm_str, "string": s_val})
                if len(str_hits) >= max_matches:
                    break
        if len(str_hits) >= max_matches:
            break

    # Scan executable segments for 7-byte RIP-relative LEA/MOV (48 8D xx / 4C 8D xx / 48 8B xx)
    xrefs: list[dict[str, Any]] = []
    if target_vaddrs:
        exec_segs = [s for s in segs if s.is_exec]
        for seg in exec_segs:
            blob = data[seg.p_offset : seg.p_offset + seg.p_filesz]
            blen = len(blob)
            i = 0
            while i < blen - 7 and len(xrefs) < max_matches * 2:
                b0 = blob[i]
                if b0 in (0x48, 0x4C) and blob[i + 1] in (0x8D, 0x8B):
                    modrm = blob[i + 2]
                    # ModRM mod=00, rm=101 -> [rip + disp32]
                    if (modrm & 0xC7) == 0x05:
                        (disp,) = struct.unpack_from("<i", blob, i + 3)
                        ins_va = seg.p_vaddr + i
                        eff_va = ins_va + 7 + disp
                        if eff_va in target_vaddrs:
                            xrefs.append(
                                {
                                    "code_vaddr": hex(ins_va),
                                    "string_vaddr": hex(eff_va),
                                    "string": target_vaddrs[eff_va],
                                    "op": "lea" if blob[i + 1] == 0x8D else "mov",
                                }
                            )
                i += 1

    return {
        "file": str(path),
        "query": search_substring,
        "strings": str_hits,
        "xrefs": xrefs,
    }


def decompile_function_summary(path: Path, func_vaddr: int, max_bytes: int = 1024) -> dict[str, Any]:
    """Produces a Mini-IDA structural summary: stack frame, calls, strings, branches, and annotated assembly."""
    data = path.read_bytes()
    segs = _load_elf_segments(data)
    off = vaddr_to_offset(segs, func_vaddr)
    if off is None:
        raise ValueError(f"Virtual address {hex(func_vaddr)} not mapped in ELF segments")

    chunk = data[off : off + max_bytes]
    insns = disassemble_bytes(chunk, func_vaddr, max_instructions=250, full_elf_data=data, elf_segs=segs)

    trimmed: list[dict[str, Any]] = []
    calls: list[str] = []
    branches: list[str] = []
    strings_ref: list[str] = []
    stack_alloc: str | None = None

    for ins in insns:
        trimmed.append(ins)
        mn = ins["mnemonic"]
        op = ins["op_str"]
        if mn == "sub" and op.startswith("rsp,") and stack_alloc is None:
            stack_alloc = op.split(",", 1)[1].strip()
        if mn == "call":
            calls.append(f"{ins['address']} -> call {op}")
        elif mn.startswith("j"):
            branches.append(f"{ins['address']} -> {mn} {op}")
        if '"' in ins["comment"]:
            strings_ref.append(f"{ins['address']}: {ins['comment']}")
        if mn in ("ret", "retn") and len(trimmed) > 3:
            break

    return {
        "function_vaddr": hex(func_vaddr),
        "instruction_count": len(trimmed),
        "stack_frame_bytes": stack_alloc,
        "calls": calls,
        "branches": branches,
        "referenced_strings": strings_ref,
        "disassembly": trimmed,
    }


def binary_diff_files(file_a: Path, file_b: Path, max_diffs: int = 64) -> dict[str, Any]:
    a = file_a.read_bytes()
    b = file_b.read_bytes()
    min_len = min(len(a), len(b))
    diffs: list[dict[str, Any]] = []
    i = 0
    while i < min_len and len(diffs) < max_diffs:
        if a[i] != b[i]:
            start = i
            while i < min_len and a[i] != b[i] and (i - start) < 32:
                i += 1
            diffs.append(
                {
                    "offset": hex(start),
                    "length": i - start,
                    "original_hex": a[start:i].hex(),
                    "modified_hex": b[start:i].hex(),
                }
            )
        else:
            i += 1
    return {
        "file_a": str(file_a),
        "file_b": str(file_b),
        "size_a": len(a),
        "size_b": len(b),
        "diff_blocks": diffs,
    }


def generate_goldhen_patch_json(
    title: str,
    title_id: str,
    app_ver: str,
    patch_name: str,
    author: str,
    patch_entries: list[dict[str, str]],
    out_path: Path,
) -> dict[str, Any]:
    """
    Exports a standard GoldHEN Cheat/Patch JSON file ready to copy to
    /data/GoldHEN/patches/json/<TITLEID>.json on the PS4!
    Each entry in patch_entries: {"offset": "0x123456", "on": "90909090", "off": "8945fc"}
    """
    payload = {
        "patch": [
            {
                "title": title,
                "app_titleid": [title_id],
                "app_ver": app_ver,
                "name": patch_name,
                "author": author,
                "note": "Generated by PS4DeepMCP Sovereign RE Engine",
                "patch_list": [
                    {
                        "type": "bytes",
                        "addr": e["offset"],
                        "value": e["on"],
                        "orig": e.get("off", ""),
                    }
                    for e in patch_entries
                ],
            }
        ]
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {"saved_to": str(out_path), "remote_goldhen_path": f"/data/GoldHEN/patches/json/{title_id}.json", "patch": payload}
