"""
GoldHEN Infrastructure Bridge:
- Full Root FTP Filesystem (port 2121) + recursive LAN game dumper
- Safe Orbis SQLite DB pull/backup/query/push
- GoldHEN BinLoader payload injector (port 9090)
- GoldHEN KLog live kernel log reader (port 3232)
- Remote PKG Installer (port 12800) + ephemeral local HTTP PKG server
- Background Auto-Payload Watcher (auto-re-injects ps4debug-NG after reboots)
"""

from __future__ import annotations

import ftplib
import http.server
import io
import json
import shutil
import socket
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from typing import Any


def get_lan_ip_for_target(target_ip: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_ip, 9090))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


class GoldHENBridge:
    def __init__(self, cfg: dict[str, Any], root_dir: Path):
        self.cfg = cfg
        self.root_dir = root_dir
        self._watcher_thread: threading.Thread | None = None
        self._watcher_stop = threading.Event()
        self._watcher_log: list[str] = []
        self._pkg_server: http.server.ThreadingHTTPServer | None = None
        self._pkg_thread: threading.Thread | None = None

    @property
    def host(self) -> str:
        return self.cfg["target"]["ip"]

    @property
    def timeout(self) -> float:
        return float(self.cfg["target"].get("timeout_sec", 8.0))

    def _port(self, name: str, default: int) -> int:
        return int(self.cfg.get("ports", {}).get(name, default))

    def _ftp_connect(self) -> ftplib.FTP:
        ftp = ftplib.FTP()
        ftp.connect(self.host, self._port("ftp", 2121), timeout=self.timeout)
        auth = self.cfg.get("ftp_auth", {})
        ftp.login(auth.get("username", "anonymous"), auth.get("password", ""))
        return ftp

    # =========================================================================
    # PORT PROBE & NETWORK HEALTH
    # =========================================================================
    def probe_services(self) -> dict[str, Any]:
        ports = self.cfg.get("ports", {})
        results: dict[str, Any] = {"target_ip": self.host, "services": {}}
        for name in ("ps4debug", "ftp", "binloader", "rpi", "klog"):
            p = int(ports.get(name, 0))
            if not p:
                continue
            t0 = time.perf_counter()
            ok = False
            err = None
            try:
                with socket.create_connection((self.host, p), timeout=1.5):
                    ok = True
            except OSError as e:
                err = str(e)
            results["services"][name] = {
                "port": p,
                "online": ok,
                "latency_ms": round((time.perf_counter() - t0) * 1000, 1),
                "error": err,
            }
        return results

    # =========================================================================
    # ROOT FILESYSTEM (GOLDHEN FTP PORT 2121)
    # =========================================================================
    def fs_list(self, remote_path: str = "/") -> list[dict[str, Any]]:
        lines: list[str] = []
        with self._ftp_connect() as ftp:
            ftp.cwd(remote_path)
            ftp.retrlines("LIST", lines.append)
        entries: list[dict[str, Any]] = []
        for line in lines:
            parts = line.split(maxsplit=8)
            if len(parts) >= 9:
                perms, _, owner, group, size_s, mon, day, tm, name = parts
                entries.append(
                    {
                        "name": name,
                        "is_dir": perms.startswith("d"),
                        "perms": perms,
                        "size": int(size_s) if size_s.isdigit() else 0,
                        "raw": line,
                    }
                )
            else:
                entries.append({"name": line, "is_dir": False, "raw": line})
        return entries

    def fs_pull(self, remote_path: str, local_path: Path) -> dict[str, Any]:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        with self._ftp_connect() as ftp, local_path.open("wb") as f:
            ftp.retrbinary(f"RETR {remote_path}", f.write, blocksize=65536)
        return {
            "remote_path": remote_path,
            "local_path": str(local_path),
            "bytes": local_path.stat().st_size,
        }

    def fs_push(self, local_path: Path, remote_path: str) -> dict[str, Any]:
        if not local_path.is_file():
            raise FileNotFoundError(f"Local file not found: {local_path}")
        parent = "/".join(remote_path.rstrip("/").split("/")[:-1]) or "/"
        with self._ftp_connect() as ftp:
            self._ftp_mkdirs(ftp, parent)
            with local_path.open("rb") as f:
                ftp.storbinary(f"STOR {remote_path}", f, blocksize=65536)
        return {
            "local_path": str(local_path),
            "remote_path": remote_path,
            "bytes": local_path.stat().st_size,
        }

    def fs_delete(self, remote_path: str) -> dict[str, Any]:
        with self._ftp_connect() as ftp:
            ftp.delete(remote_path)
        return {"deleted": remote_path}

    @staticmethod
    def _ftp_mkdirs(ftp: ftplib.FTP, remote_dir: str) -> None:
        cur = ""
        for part in remote_dir.strip("/").split("/"):
            if not part:
                continue
            cur += "/" + part
            try:
                ftp.mkd(cur)
            except ftplib.error_perm:
                pass

    def fs_mirror_dir(
        self,
        remote_dir: str,
        local_dir: Path,
        max_files: int = 500,
        max_total_mb: int = 2048,
    ) -> dict[str, Any]:
        """Recursively pulls a PS4 directory (e.g. decrypted PFS game mount) over gigabit LAN."""
        local_dir.mkdir(parents=True, exist_ok=True)
        pulled: list[str] = []
        skipped: list[str] = []
        total_bytes = 0
        byte_cap = max_total_mb * 1024 * 1024

        def walk(ftp: ftplib.FTP, rdir: str, ldir: Path) -> None:
            nonlocal total_bytes
            lines: list[str] = []
            try:
                ftp.cwd(rdir)
                ftp.retrlines("LIST", lines.append)
            except ftplib.all_errors as e:
                skipped.append(f"{rdir}: {e}")
                return

            for line in lines:
                if len(pulled) >= max_files or total_bytes >= byte_cap:
                    return
                parts = line.split(maxsplit=8)
                if len(parts) < 9:
                    continue
                perms, _, _, _, size_s, _, _, _, name = parts
                if name in (".", ".."):
                    continue
                r_child = f"{rdir.rstrip('/')}/{name}"
                l_child = ldir / name
                if perms.startswith("d"):
                    l_child.mkdir(parents=True, exist_ok=True)
                    walk(ftp, r_child, l_child)
                else:
                    fsize = int(size_s) if size_s.isdigit() else 0
                    if total_bytes + fsize > byte_cap:
                        skipped.append(f"{r_child} (exceeds {max_total_mb}MB cap)")
                        continue
                    try:
                        with l_child.open("wb") as out_f:
                            ftp.retrbinary(f"RETR {r_child}", out_f.write, blocksize=65536)
                        sz = l_child.stat().st_size
                        total_bytes += sz
                        pulled.append(r_child)
                    except ftplib.all_errors as e:
                        skipped.append(f"{r_child}: {e}")

        with self._ftp_connect() as ftp:
            walk(ftp, remote_dir, local_dir)

        return {
            "remote_dir": remote_dir,
            "local_dir": str(local_dir),
            "files_pulled": len(pulled),
            "total_bytes": total_bytes,
            "skipped_count": len(skipped),
            "skipped_sample": skipped[:20],
        }

    # =========================================================================
    # SAFE ORBIS SQLITE DATABASE ENGINE (app.db / addcont.db / notification.db)
    # =========================================================================
    def query_orbis_db(
        self,
        remote_db_path: str,
        sql: str,
        write_back: bool = False,
        backups_dir: Path | None = None,
    ) -> dict[str, Any]:
        bdir = backups_dir or (self.root_dir / "backups")
        bdir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        base_name = Path(remote_db_path).name
        backup_file = bdir / f"{base_name}.{ts}.bak"
        work_file = bdir / f"{base_name}.work.db"

        self.fs_pull(remote_db_path, backup_file)
        shutil.copy2(backup_file, work_file)

        rows_out: list[dict[str, Any]] = []
        affected = 0
        with sqlite3.connect(work_file) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.execute(sql)
            if cur.description:
                rows_out = [dict(r) for r in cur.fetchall()]
            else:
                affected = cur.rowcount
                conn.commit()

        pushed = False
        if write_back:
            self.fs_push(work_file, remote_db_path)
            pushed = True

        return {
            "remote_db": remote_db_path,
            "backup_saved": str(backup_file),
            "pushed_back": pushed,
            "rows_returned": len(rows_out),
            "rows_affected": affected,
            "rows": rows_out[:200],
        }

    # =========================================================================
    # GOLDHEN BINLOADER (PORT 9090) & KLOG (PORT 3232)
    # =========================================================================
    def send_payload(self, payload_path: Path) -> dict[str, Any]:
        if not payload_path.is_file():
            raise FileNotFoundError(f"Payload not found: {payload_path}")
        data = payload_path.read_bytes()
        port = self._port("binloader", 9090)
        with socket.create_connection((self.host, port), timeout=self.timeout) as s:
            s.sendall(data)
        return {
            "host": self.host,
            "port": port,
            "payload": str(payload_path),
            "bytes_sent": len(data),
        }

    def read_klog(self, duration_sec: float = 2.5, max_bytes: int = 65536) -> dict[str, Any]:
        port = self._port("klog", 3232)
        buf = bytearray()
        deadline = time.monotonic() + duration_sec
        with socket.create_connection((self.host, port), timeout=self.timeout) as s:
            s.settimeout(0.4)
            while time.monotonic() < deadline and len(buf) < max_bytes:
                try:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf.extend(chunk)
                except socket.timeout:
                    continue
        text = buf.decode("utf-8", errors="replace")
        return {"port": port, "bytes": len(buf), "lines": text.splitlines()[-200:]}

    # =========================================================================
    # REMOTE PKG INSTALLER (PORT 12800) + LOCAL LAN HTTP SERVER
    # =========================================================================
    def install_pkg_over_lan(self, pkg_path: Path) -> dict[str, Any]:
        if not pkg_path.is_file():
            raise FileNotFoundError(f"PKG not found: {pkg_path}")
        http_port = self._port("local_http_pkg_server", 8899)
        serve_dir = pkg_path.parent
        self._ensure_pkg_http_server(serve_dir, http_port)

        lan_ip = get_lan_ip_for_target(self.host)
        encoded_name = urllib.parse.quote(pkg_path.name)
        pkg_url = f"http://{lan_ip}:{http_port}/{encoded_name}"

        rpi_port = self._port("rpi", 12800)
        body = json.dumps({"type": "direct", "packages": [pkg_url]}).encode("utf-8")
        req = urllib.request.Request(
            f"http://{self.host}:{rpi_port}/api/install",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            resp_text = resp.read().decode("utf-8", errors="replace")
        return {
            "pkg_url": pkg_url,
            "rpi_endpoint": f"http://{self.host}:{rpi_port}/api/install",
            "rpi_response": resp_text,
        }

    def _ensure_pkg_http_server(self, directory: Path, port: int) -> None:
        if self._pkg_server is not None:
            self._pkg_server.shutdown()
            self._pkg_server.server_close()
            self._pkg_server = None
        handler = partial(http.server.SimpleHTTPRequestHandler, directory=str(directory))
        self._pkg_server = http.server.ThreadingHTTPServer(("0.0.0.0", port), handler)
        self._pkg_thread = threading.Thread(target=self._pkg_server.serve_forever, daemon=True)
        self._pkg_thread.start()

    # =========================================================================
    # AUTO-RECONNECT / AUTO-PAYLOAD WATCHER (SURVIVES REBOOTS AUTOMATICALLY)
    # =========================================================================
    def start_auto_watcher(self, payloads: list[str], poll_sec: float = 4.0) -> dict[str, Any]:
        if self._watcher_thread and self._watcher_thread.is_alive():
            return {"status": "already_running", "log": self._watcher_log[-20:]}
        self._watcher_stop.clear()

        def loop() -> None:
            was_online = False
            while not self._watcher_stop.is_set():
                bin_up = False
                dbg_up = False
                try:
                    with socket.create_connection((self.host, self._port("binloader", 9090)), timeout=1.0):
                        bin_up = True
                except OSError:
                    pass
                try:
                    with socket.create_connection((self.host, self._port("ps4debug", 744)), timeout=1.0):
                        dbg_up = True
                except OSError:
                    pass

                if bin_up and not dbg_up and (not was_online or payloads):
                    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
                    self._watcher_log.append(f"[{ts}] GoldHEN BinLoader detected -> injecting {len(payloads)} payloads")
                    for p in payloads:
                        try:
                            self.send_payload(Path(p))
                            self._watcher_log.append(f"[{ts}] Injected {Path(p).name}")
                            time.sleep(1.0)
                        except Exception as e:
                            self._watcher_log.append(f"[{ts}] Failed {p}: {e}")
                    was_online = True
                elif not bin_up:
                    was_online = False
                self._watcher_stop.wait(poll_sec)

        self._watcher_thread = threading.Thread(target=loop, daemon=True)
        self._watcher_thread.start()
        return {"status": "started", "payloads": payloads, "poll_sec": poll_sec}

    def stop_auto_watcher(self) -> dict[str, Any]:
        self._watcher_stop.set()
        return {"status": "stopped", "log": self._watcher_log[-20:]}

    def watcher_status(self) -> dict[str, Any]:
        return {
            "running": bool(self._watcher_thread and self._watcher_thread.is_alive()),
            "log": self._watcher_log[-30:],
        }
