# PS4DeepMCP — Sovereign Deep-Access MCP Server (PS4 Pro FW 13.02)

Full-spectrum MCP server exposing **38 tools** across `ps4debug-NG` (port `744`), GoldHEN FTP (`2121`), GoldHEN BinLoader (`9090`), KLog (`3232`), Remote PKG Installer (`12800`), a pure-Python **Mini-IDA Pro x86-64 reverse-engineering engine** (Capstone 5 + RIP-relative string xrefs + function recovery + ELF64 live RAM dumper), an **Animated Wallpaper & ATRAC9 Theme Studio**, and an **Offline-Cached HTML5 AppCache 13.02 Exploit Host + Auto-Payload Reboot Watcher**.

## Quick Setup

1. Edit `config.json` and set your PS4 Pro's LAN IP (`target.ip`) and user ID (`target.user_id`, visible under `/user/home/` via `ps4_fs_ls("/user/home")`).
2. Add this entry to your MCP client config (Antigravity / Claude / Cursor):

```json
{
  "mcpServers": {
    "ps4-deep-mcp": {
      "command": "py",
      "args": ["-3", "C:/Users/Administrator/Desktop/Tools/PS4DeepMCP/server.py"]
    }
  }
}
```

3. Optional external tools (drop paths into `config.json -> external_tools` when available):
   - `at9tool` or `vgaudio_cli` for encoding 48kHz WAV $\to$ Sony `.at9` BGM audio.
   - `ffmpeg` for MP4/WebM animated frame extraction and MP3 decoding.
   - Drop your `ps4debug-NG.bin` into `exploit_files/` and add its path to `auto_watcher.startup_payloads` for automatic post-reboot re-injection.
