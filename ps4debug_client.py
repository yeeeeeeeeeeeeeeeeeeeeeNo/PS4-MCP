"""
Full ps4debug-NG Binary TCP Protocol Client + High-Level Live Memory & ELF Dumper.
Supports PS4 Pro FW 13.02 running GoldHEN + ps4debug-NG (default port 744).
"""

from __future__ import annotations

import re
import socket
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

CMD_PACKET_MAGIC = 0xFFAABBCC

# ps4debug-NG Command Opcodes
CMD_VERSION = 0xBD000001

CMD_PROC_LIST = 0xBDAA0001
CMD_PROC_READ = 0xBDAA0002
CMD_PROC_WRITE = 0xBDAA0003
CMD_PROC_MAPS = 0xBDAA0004
CMD_PROC_INTALL = 0xBDAA0005
CMD_PROC_CALL = 0xBDAA0006
CMD_PROC_ELF = 0xBDAA0007
CMD_PROC_PROTECT = 0xBDAA0008
CMD_PROC_SCAN = 0xBDAA0009
CMD_PROC_INFO = 0xBDAA000A
CMD_PROC_ALLOC = 0xBDAA000B
CMD_PROC_FREE = 0xBDAA000C

CMD_DEBUG_ATTACH = 0xBDBB0001
CMD_DEBUG_DETACH = 0xBDBB0002
CMD_DEBUG_BREAKPT = 0xBDBB0003
CMD_DEBUG_WATCHPT = 0xBDBB0004
CMD_DEBUG_THREADS = 0xBDBB0005
CMD_DEBUG_STOPTHR = 0xBDBB0006
CMD_DEBUG_RESUMETHR = 0xBDBB0007
CMD_DEBUG_GETREGS = 0xBDBB0008
CMD_DEBUG_SETREGS = 0xBDBB0009
CMD_DEBUG_STOPGO = 0xBDBB000E
CMD_DEBUG_THRINFO = 0xBDBB000F
CMD_DEBUG_SINGLESTEP = 0xBDBB0010

CMD_KERN_BASE = 0xBDCC0001
CMD_KERN_READ = 0xBDCC0002
CMD_KERN_WRITE = 0xBDCC0003

CMD_CONSOLE_REBOOT = 0xBDDD0001
CMD_CONSOLE_NOTIFY = 0xBDDD0004
CMD_CONSOLE_INFO = 0xBDDD0005

CMD_SUCCESS = 0x80000000
CMD_ERROR = 0xF0000001
CMD_TOO_MUCH_DATA = 0xF0000002
CMD_DATA_NULL = 0xF0000003
CMD_ALREADY_DEBUG = 0xF0000004
CMD_INVALID_INDEX = 0xF0000005

# Protection bitflags (Orbis/FreeBSD vm_prot_t)
PROT_READ = 0x1
PROT_WRITE = 0x2
PROT_EXEC = 0x4
PROT_RWX = PROT_READ | PROT_WRITE | PROT_EXEC

NET_MAX_LENGTH = 8192


@dataclass
class ProcessEntry:
    name: str
    pid: int


@dataclass
class MemoryMapEntry:
    name: str
    start: int
    end: int
    offset: int
    prot: int

    @property
    def size(self) -> int:
        return max(0, self.end - self.start)

    @property
    def prot_str(self) -> str:
        r = "r" if (self.prot & PROT_READ) else "-"
        w = "w" if (self.prot & PROT_WRITE) else "-"
        x = "x" if (self.prot & PROT_EXEC) else "-"
        return f"{r}{w}{x}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "start": hex(self.start),
            "end": hex(self.end),
            "size": self.size,
            "offset": hex(self.offset),
            "prot": self.prot_str,
            "prot_bits": self.prot,
        }


class PS4DebugError(RuntimeError):
    pass


class PS4DebugClient:
    """Thread-safe per-command TCP client for ps4debug-NG."""

    def __init__(self, host: str, port: int = 744, timeout: float = 8.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._patch_ledger: list[dict[str, Any]] = []

    def _connect(self) -> socket.socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect((self.host, self.port))
        return s

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        chunks = bytearray()
        while len(chunks) < n:
            part = sock.recv(n - len(chunks))
            if not part:
                raise PS4DebugError(f"Connection closed early (wanted {n} bytes, got {len(chunks)})")
            chunks.extend(part)
        return bytes(chunks)

    @staticmethod
    def _send_packet(sock: socket.socket, cmd: int, payload: bytes = b"") -> None:
        header = struct.pack("<III", CMD_PACKET_MAGIC, cmd, len(payload))
        sock.sendall(header + payload)

    @classmethod
    def _check_status(cls, sock: socket.socket) -> int:
        raw = cls._recv_exact(sock, 4)
        (status,) = struct.unpack("<I", raw)
        if status != CMD_SUCCESS:
            raise PS4DebugError(f"ps4debug-NG returned error status 0x{status:08X}")
        return status

    @classmethod
    def _recv_chunked(cls, sock: socket.socket, length: int) -> bytes:
        buf = bytearray()
        remaining = length
        while remaining > 0:
            chunk = min(remaining, NET_MAX_LENGTH)
            buf.extend(cls._recv_exact(sock, chunk))
            remaining -= chunk
        return bytes(buf)

    @staticmethod
    def _send_chunked(sock: socket.socket, data: bytes) -> None:
        view = memoryview(data)
        offset = 0
        total = len(data)
        while offset < total:
            end = min(offset + NET_MAX_LENGTH, total)
            sock.sendall(view[offset:end])
            offset = end

    # =========================================================================
    # SYSTEM & VERSION
    # =========================================================================
    def version(self) -> str:
        with self._connect() as s:
            self._send_packet(s, CMD_VERSION)
            (length,) = struct.unpack("<I", self._recv_exact(s, 4))
            return self._recv_exact(s, length).decode("utf-8", errors="replace").rstrip("\x00")

    def notify(self, message: str, msg_type: int = 222) -> None:
        msg_bytes = message.encode("utf-8") + b"\x00"
        payload = struct.pack("<II", msg_type, len(msg_bytes))
        with self._connect() as s:
            self._send_packet(s, CMD_CONSOLE_NOTIFY, payload)
            self._send_chunked(s, msg_bytes)
            self._check_status(s)

    def console_info(self) -> dict[str, Any]:
        with self._connect() as s:
            self._send_packet(s, CMD_CONSOLE_INFO)
            self._check_status(s)
            data = self._recv_exact(s, 128)
            return {"raw_hex": data.hex(), "ascii": data.decode("ascii", errors="ignore").strip("\x00")}

    def reboot(self) -> None:
        with self._connect() as s:
            self._send_packet(s, CMD_CONSOLE_REBOOT)

    # =========================================================================
    # KERNEL ACCESS
    # =========================================================================
    def kernel_base(self) -> int:
        with self._connect() as s:
            self._send_packet(s, CMD_KERN_BASE)
            self._check_status(s)
            (base,) = struct.unpack("<Q", self._recv_exact(s, 8))
            return base

    def kernel_read(self, address: int, length: int) -> bytes:
        payload = struct.pack("<QI", address, length)
        with self._connect() as s:
            self._send_packet(s, CMD_KERN_READ, payload)
            self._check_status(s)
            return self._recv_chunked(s, length)

    def kernel_write(self, address: int, data: bytes) -> None:
        payload = struct.pack("<QI", address, len(data))
        with self._connect() as s:
            self._send_packet(s, CMD_KERN_WRITE, payload)
            self._check_status(s)
            self._send_chunked(s, data)
            self._check_status(s)

    # =========================================================================
    # PROCESS & LIVE MEMORY ACCESS
    # =========================================================================
    def process_list(self) -> list[ProcessEntry]:
        with self._connect() as s:
            self._send_packet(s, CMD_PROC_LIST)
            self._check_status(s)
            (count,) = struct.unpack("<I", self._recv_exact(s, 4))
            raw = self._recv_chunked(s, count * 36)
        out: list[ProcessEntry] = []
        for i in range(count):
            entry = raw[i * 36 : (i + 1) * 36]
            name = entry[:32].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            (pid,) = struct.unpack("<I", entry[32:36])
            out.append(ProcessEntry(name=name, pid=pid))
        return out

    def process_maps(self, pid: int) -> list[MemoryMapEntry]:
        payload = struct.pack("<I", pid)
        with self._connect() as s:
            self._send_packet(s, CMD_PROC_MAPS, payload)
            self._check_status(s)
            (count,) = struct.unpack("<I", self._recv_exact(s, 4))
            raw = self._recv_chunked(s, count * 58)
        maps: list[MemoryMapEntry] = []
        for i in range(count):
            rec = raw[i * 58 : (i + 1) * 58]
            name = rec[:32].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
            start, end, offset, prot = struct.unpack("<QQQH", rec[32:58])
            maps.append(MemoryMapEntry(name=name, start=start, end=end, offset=offset, prot=prot))
        return maps

    def process_info(self, pid: int) -> dict[str, Any]:
        payload = struct.pack("<I", pid)
        with self._connect() as s:
            self._send_packet(s, CMD_PROC_INFO, payload)
            self._check_status(s)
            raw = self._recv_exact(s, 188)
        r_pid = struct.unpack("<I", raw[0:4])[0]
        name = raw[4:44].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        path = raw[44:108].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        title_id = raw[108:124].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        content_id = raw[124:188].split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        return {
            "pid": r_pid,
            "name": name,
            "path": path,
            "title_id": title_id,
            "content_id": content_id,
        }

    def read_memory(self, pid: int, address: int, length: int) -> bytes:
        # Chunk large reads safely to stay responsive over LAN
        max_call = 512 * 1024
        if length <= max_call:
            payload = struct.pack("<IQI", pid, address, length)
            with self._connect() as s:
                self._send_packet(s, CMD_PROC_READ, payload)
                self._check_status(s)
                return self._recv_chunked(s, length)
        out = bytearray()
        pos = 0
        while pos < length:
            step = min(max_call, length - pos)
            out.extend(self.read_memory(pid, address + pos, step))
            pos += step
        return bytes(out)

    def write_memory(self, pid: int, address: int, data: bytes) -> None:
        payload = struct.pack("<IQI", pid, address, len(data))
        with self._connect() as s:
            self._send_packet(s, CMD_PROC_WRITE, payload)
            self._check_status(s)
            self._send_chunked(s, data)
            self._check_status(s)

    def protect_memory(self, pid: int, address: int, length: int, new_prot: int) -> None:
        payload = struct.pack("<IQII", pid, address, length, new_prot)
        with self._connect() as s:
            self._send_packet(s, CMD_PROC_PROTECT, payload)
            self._check_status(s)

    def allocate_memory(self, pid: int, length: int) -> int:
        payload = struct.pack("<II", pid, length)
        with self._connect() as s:
            self._send_packet(s, CMD_PROC_ALLOC, payload)
            self._check_status(s)
            (addr,) = struct.unpack("<Q", self._recv_exact(s, 8))
            return addr

    def free_memory(self, pid: int, address: int, length: int) -> None:
        payload = struct.pack("<IQI", pid, address, length)
        with self._connect() as s:
            self._send_packet(s, CMD_PROC_FREE, payload)
            self._check_status(s)

    def install_rpc(self, pid: int) -> int:
        payload = struct.pack("<I", pid)
        with self._connect() as s:
            self._send_packet(s, CMD_PROC_INTALL, payload)
            self._check_status(s)
            (rpc_stub,) = struct.unpack("<Q", self._recv_exact(s, 8))
            return rpc_stub

    def call_function(
        self,
        pid: int,
        rpc_stub: int,
        address: int,
        args: list[int] | None = None,
    ) -> int:
        regs = (args or [])[:6]
        while len(regs) < 6:
            regs.append(0)
        payload = struct.pack("<IQQQQQQQQ", pid, address, rpc_stub, *regs)
        with self._connect() as s:
            self._send_packet(s, CMD_PROC_CALL, payload)
            self._check_status(s)
            _, rax = struct.unpack("<IQ", self._recv_exact(s, 12))
            return rax

    def inject_elf(self, pid: int, elf_bytes: bytes) -> int:
        payload = struct.pack("<II", pid, len(elf_bytes))
        with self._connect() as s:
            self._send_packet(s, CMD_PROC_ELF, payload)
            self._send_chunked(s, elf_bytes)
            self._check_status(s)
            (entry_point,) = struct.unpack("<Q", self._recv_exact(s, 8))
            return entry_point

    # =========================================================================
    # HARDWARE DEBUGGER PRIMITIVES
    # =========================================================================
    def debug_attach(self, pid: int) -> None:
        with self._connect() as s:
            self._send_packet(s, CMD_DEBUG_ATTACH, struct.pack("<I", pid))
            self._check_status(s)

    def debug_detach(self) -> None:
        with self._connect() as s:
            self._send_packet(s, CMD_DEBUG_DETACH)
            self._check_status(s)

    def debug_threads(self) -> list[int]:
        with self._connect() as s:
            self._send_packet(s, CMD_DEBUG_THREADS)
            self._check_status(s)
            (count,) = struct.unpack("<I", self._recv_exact(s, 4))
            raw = self._recv_chunked(s, count * 4)
        return list(struct.unpack(f"<{count}I", raw))

    def debug_get_regs(self, lwpid: int) -> dict[str, str]:
        with self._connect() as s:
            self._send_packet(s, CMD_DEBUG_GETREGS, struct.pack("<I", lwpid))
            self._check_status(s)
            raw = self._recv_exact(s, 176)
        reg_names = [
            "r15", "r14", "r13", "r12", "r11", "r10", "r9", "r8",
            "rdi", "rsi", "rbp", "rbx", "rdx", "rcx", "rax",
            "trapno", "fs_gs_es_ds", "err", "rip", "cs", "rflags", "rsp", "ss",
        ]
        vals = struct.unpack("<22Q", raw[:176])
        return {name: hex(val) for name, val in zip(reg_names, vals)}

    # =========================================================================
    # HIGH-LEVEL MEMORY & REVERSE ENGINEERING HELPERS
    # =========================================================================
    @staticmethod
    def compile_aob_regex(pattern: str) -> re.Pattern[bytes]:
        tokens = pattern.strip().split()
        regex_parts: list[bytes] = []
        for tok in tokens:
            if tok in ("?", "??", "*"):
                regex_parts.append(b".")
            else:
                b = bytes([int(tok, 16)])
                regex_parts.append(re.escape(b))
        return re.compile(b"".join(regex_parts), re.DOTALL)

    def aob_scan(
        self,
        pid: int,
        pattern: str,
        module_filter: str | None = None,
        executable_only: bool = False,
        max_results: int = 32,
    ) -> list[dict[str, Any]]:
        rx = self.compile_aob_regex(pattern)
        maps = self.process_maps(pid)
        hits: list[dict[str, Any]] = []

        for m in maps:
            if not (m.prot & PROT_READ):
                continue
            if executable_only and not (m.prot & PROT_EXEC):
                continue
            if module_filter and module_filter.lower() not in m.name.lower():
                continue
            if m.size == 0 or m.size > 256 * 1024 * 1024:
                continue

            chunk_size = 1024 * 1024
            overlap = max(64, len(pattern.split()) * 2)
            offset = 0
            while offset < m.size and len(hits) < max_results:
                read_len = min(chunk_size, m.size - offset)
                try:
                    data = self.read_memory(pid, m.start + offset, read_len)
                except PS4DebugError:
                    break
                for match in rx.finditer(data):
                    hit_addr = m.start + offset + match.start()
                    hits.append(
                        {
                            "address": hex(hit_addr),
                            "module": m.name,
                            "module_offset": hex(hit_addr - m.start),
                            "prot": m.prot_str,
                            "matched_hex": match.group(0).hex(),
                        }
                    )
                    if len(hits) >= max_results:
                        break
                if offset + read_len >= m.size:
                    break
                offset += chunk_size - overlap
        return hits

    def resolve_pointer_chain(self, pid: int, base_addr: int, offsets: list[int]) -> dict[str, Any]:
        current = base_addr
        steps = [hex(current)]
        for i, off in enumerate(offsets):
            raw = self.read_memory(pid, current, 8)
            (ptr,) = struct.unpack("<Q", raw)
            current = ptr + off
            steps.append(f"*(step {i})={hex(ptr)} + {hex(off)} -> {hex(current)}")
        return {"final_address": hex(current), "chain": steps}

    def patch_bytes_safe(self, pid: int, address: int, new_bytes: bytes) -> dict[str, Any]:
        """Reversible live byte-patching with LIFO page-protection lift & restore."""
        maps = self.process_maps(pid)
        owner = next((m for m in maps if m.start <= address < m.end), None)
        orig_prot = owner.prot if owner else (PROT_READ | PROT_EXEC)
        orig_bytes = self.read_memory(pid, address, len(new_bytes))

        page_addr = address & ~0xFFF
        page_len = ((address - page_addr) + len(new_bytes) + 0xFFF) & ~0xFFF

        lifted = False
        try:
            if not (orig_prot & PROT_WRITE):
                self.protect_memory(pid, page_addr, page_len, PROT_RWX)
                lifted = True
            self.write_memory(pid, address, new_bytes)
        finally:
            if lifted:
                self.protect_memory(pid, page_addr, page_len, orig_prot)

        entry = {
            "pid": pid,
            "address": hex(address),
            "module": owner.name if owner else "unknown",
            "module_offset": hex(address - owner.start) if owner else "0x0",
            "original_hex": orig_bytes.hex(),
            "patched_hex": new_bytes.hex(),
            "original_prot": orig_prot,
        }
        self._patch_ledger.append(entry)
        return entry

    def revert_last_patch(self) -> dict[str, Any]:
        if not self._patch_ledger:
            raise PS4DebugError("No recorded patches to revert")
        last = self._patch_ledger.pop()
        addr = int(last["address"], 16)
        orig = bytes.fromhex(last["original_hex"])
        self.patch_bytes_safe(last["pid"], addr, orig)
        self._patch_ledger.pop()  # remove the revert record itself
        return {"reverted": last}

    def dump_live_module_to_elf(
        self,
        pid: int,
        module_name: str,
        output_path: Path,
    ) -> dict[str, Any]:
        """
        Reads decrypted executable & data segments of a live PS4 process module
        (e.g. eboot.bin or libSce*.sprx) straight from RAM via ps4debug-NG and
        reconstructs a clean unencrypted x86-64 ELF64 binary for IDA/Ghidra/Capstone.
        """
        maps = self.process_maps(pid)
        segs = [m for m in maps if module_name.lower() in m.name.lower() and (m.prot & PROT_READ) and m.size > 0]
        if not segs:
            raise PS4DebugError(f"No readable segments matched module '{module_name}' in PID {pid}")
        segs.sort(key=lambda m: m.start)

        base_vaddr = segs[0].start
        seg_blobs: list[tuple[MemoryMapEntry, bytes]] = []
        for s in segs:
            if s.size > 128 * 1024 * 1024:
                continue
            blob = self.read_memory(pid, s.start, s.size)
            seg_blobs.append((s, blob))

        # Construct valid ELF64 x86-64 header + PT_LOAD program headers
        ehdr_size = 64
        phdr_size = 56
        phnum = len(seg_blobs)
        data_offset = ((ehdr_size + phnum * phdr_size) + 0xFFF) & ~0xFFF

        e_ident = b"\x7fELF\x02\x01\x01\x09" + b"\x00" * 8  # ELF64 LE FreeBSD/Orbis
        ehdr = struct.pack(
            "<16sHHIQQQIHHHHHH",
            e_ident,
            3,              # ET_DYN (PIE)
            62,             # EM_X86_64
            1,              # EV_CURRENT
            base_vaddr,     # e_entry
            ehdr_size,      # e_phoff
            0,              # e_shoff
            0,              # e_flags
            ehdr_size,      # e_ehsize
            phdr_size,      # e_phentsize
            phnum,          # e_phnum
            64,             # e_shentsize
            0,              # e_shnum
            0,              # e_shstrndx
        )

        phdrs = bytearray()
        payload = bytearray()
        cur_off = data_offset

        for seg, blob in seg_blobs:
            p_flags = 0
            if seg.prot & PROT_EXEC:
                p_flags |= 1  # PF_X
            if seg.prot & PROT_WRITE:
                p_flags |= 2  # PF_W
            if seg.prot & PROT_READ:
                p_flags |= 4  # PF_R
            phdrs.extend(
                struct.pack(
                    "<IIQQQQQQ",
                    1,              # PT_LOAD
                    p_flags,
                    cur_off,        # p_offset
                    seg.start,      # p_vaddr
                    seg.start,      # p_paddr
                    len(blob),      # p_filesz
                    len(blob),      # p_memsz
                    0x1000,         # p_align
                )
            )
            payload.extend(blob)
            pad = ((len(blob) + 0xFFF) & ~0xFFF) - len(blob)
            if pad:
                payload.extend(b"\x00" * pad)
            cur_off += len(blob) + pad

        header_pad = data_offset - (len(ehdr) + len(phdrs))
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("wb") as f:
            f.write(ehdr)
            f.write(phdrs)
            f.write(b"\x00" * header_pad)
            f.write(payload)

        return {
            "output_path": str(output_path),
            "pid": pid,
            "module": module_name,
            "base_vaddr": hex(base_vaddr),
            "segments_dumped": len(seg_blobs),
            "total_bytes": output_path.stat().st_size,
            "segments": [s.to_dict() for s, _ in seg_blobs],
        }
