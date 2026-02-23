"""
ATLAS Restricted Web Terminal

Provides a WebSocket terminal-like interface with a strict allowlist.
No raw shell access is exposed in safe mode.
"""

from __future__ import annotations

import asyncio
import json
import logging
import shlex
import stat
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect

from api.routes.auth import get_db, get_session
from atlas.checks.registry import CheckRegistry
from atlas.utils.config import get_config

logger = logging.getLogger("atlas.terminal")
router = APIRouter(prefix="/terminal", tags=["Terminal"])


async def authenticate_ws(token: str) -> dict[str, str] | None:
    """Validate WebSocket token and return user info if authorized."""
    session = get_session(token)
    if not session:
        return None

    db = get_db()
    user = db.get_user_by_username(session["username"])
    if not user:
        return None

    # Only pentester and admin can use terminal
    if user.role not in ("pentester", "admin"):
        return None

    return {
        "username": user.username,
        "name": user.name,
        "role": user.role,
    }


class RestrictedTerminalSession:
    """Holds per-session restricted terminal state and command handlers."""

    def __init__(self, user: dict[str, str]):
        config = get_config()
        self.user = user
        self.config = config
        self.cwd = config.base_dir.resolve()
        self.allowed_roots = [config.base_dir.resolve(), config.data_dir.resolve()]
        self.last_exec_at = 0.0

    def banner(self) -> str:
        """Terminal banner text shown on connect."""
        allowed = (
            "help, clear, whoami, date, pwd, ls, cat, "
            "atlas checks, atlas scans, atlas health, exit"
        )
        return (
            "\r\n[ATLAS Restricted Terminal]\r\n"
            "Raw shell access is disabled.\r\n"
            f"Allowed commands: {allowed}\r\n"
            "Type 'help' for usage.\r\n\r\n"
        )

    def prompt(self) -> str:
        """Session prompt string."""
        return f"{self.user['username']}@atlas(restricted):~$ "

    async def execute(self, command: str) -> tuple[str, bool]:
        """Execute a validated command. Returns (output, close_session)."""
        normalized = command.strip()
        if not normalized:
            return "", False

        max_input = self.config.terminal_max_input_chars
        if len(normalized) > max_input:
            return f"[DENIED] Command too long (max {max_input} chars).\r\n", False

        # Block shell composition and substitution symbols entirely.
        blocked_tokens = [";", "&&", "||", "|", ">", "<", "`", "$("]
        if any(token in normalized for token in blocked_tokens):
            return "[DENIED] Shell operators are not allowed.\r\n", False

        now = time.monotonic()
        if now - self.last_exec_at < 0.15:
            return "[DENIED] Rate limit: please wait before running another command.\r\n", False
        self.last_exec_at = now

        try:
            args = shlex.split(normalized)
        except ValueError:
            return "[ERROR] Invalid quoting in command.\r\n", False

        if not args:
            return "", False

        command_name = args[0].lower()

        try:
            if command_name == "help":
                return self._help_text(), False
            if command_name == "clear":
                return "\x1b[2J\x1b[H", False
            if command_name == "whoami":
                return f"{self.user['username']} ({self.user['role']})\r\n", False
            if command_name == "date":
                return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC\r\n"), False
            if command_name == "pwd":
                return f"{self.cwd}\r\n", False
            if command_name == "ls":
                return await asyncio.to_thread(self._cmd_ls, args[1:]), False
            if command_name == "cat":
                return await asyncio.to_thread(self._cmd_cat, args[1:]), False
            if command_name == "atlas":
                return await asyncio.wait_for(
                    self._cmd_atlas(args[1:]),
                    timeout=self.config.terminal_command_timeout,
                ), False
            if command_name in {"exit", "quit"}:
                return "Session closed.\r\n", True
            return f"[DENIED] Command '{command_name}' is not allowed. Type 'help'.\r\n", False
        except asyncio.TimeoutError:
            return "[ERROR] Command timed out.\r\n", False
        except Exception:
            logger.exception("Terminal command execution failed")
            return "[ERROR] Command failed unexpectedly.\r\n", False

    def _help_text(self) -> str:
        return (
            "Restricted command reference:\r\n"
            "  help                 Show this help text\r\n"
            "  clear                Clear terminal screen\r\n"
            "  whoami               Show authenticated user\r\n"
            "  date                 Show current UTC timestamp\r\n"
            "  pwd                  Show current workspace path\r\n"
            "  ls [path]            List files under approved paths\r\n"
            "  cat <file>           Read a text file under approved paths\r\n"
            "  atlas checks         List registered vulnerability checks\r\n"
            "  atlas scans          Show recent scan sessions\r\n"
            "  atlas health         Show API health status\r\n"
            "  exit                 Close this terminal session\r\n"
        )

    def _resolve_path(self, raw: str) -> Path:
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = (self.cwd / candidate).resolve()
        else:
            candidate = candidate.resolve()

        for root in self.allowed_roots:
            if candidate == root or candidate.is_relative_to(root):
                return candidate
        raise PermissionError("Path is outside allowed directories")

    def _cmd_ls(self, args: list[str]) -> str:
        show_all = False
        long_format = False
        target: Path | None = None

        for arg in args:
            if arg in {"-a", "--all"}:
                show_all = True
                continue
            if arg in {"-l", "--long"}:
                long_format = True
                continue
            if arg in {"-la", "-al"}:
                show_all = True
                long_format = True
                continue
            if arg.startswith("-"):
                return f"[DENIED] Unsupported ls option: {arg}\r\n"
            if target is not None:
                return "[DENIED] Only one path argument is allowed.\r\n"
            try:
                target = self._resolve_path(arg)
            except PermissionError:
                return "[DENIED] Path is outside allowed directories.\r\n"

        if target is None:
            target = self.cwd

        if not target.exists():
            return f"[ERROR] Path not found: {target}\r\n"
        if not target.is_dir():
            return f"[ERROR] Not a directory: {target}\r\n"

        entries = sorted(
            list(target.iterdir()),
            key=lambda p: (not p.is_dir(), p.name.lower()),
        )

        lines: list[str] = []
        for entry in entries:
            if not show_all and entry.name.startswith("."):
                continue

            name = f"{entry.name}/" if entry.is_dir() else entry.name
            if not long_format:
                lines.append(name)
                continue

            st = entry.stat()
            perms = stat.filemode(st.st_mode)
            size = st.st_size
            modified = datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")
            lines.append(f"{perms} {size:>10} {modified} {name}")

        if not lines:
            return "\r\n"
        return self._truncate("\r\n".join(lines) + "\r\n")

    def _cmd_cat(self, args: list[str]) -> str:
        if len(args) != 1:
            return "[DENIED] Usage: cat <file>\r\n"

        try:
            target = self._resolve_path(args[0])
        except PermissionError:
            return "[DENIED] Path is outside allowed directories.\r\n"

        if not target.exists():
            return f"[ERROR] File not found: {target}\r\n"
        if not target.is_file():
            return "[ERROR] Target is not a file.\r\n"

        max_bytes = 128 * 1024
        if target.stat().st_size > max_bytes:
            return f"[DENIED] File too large (max {max_bytes // 1024}KB).\r\n"

        raw = target.read_bytes()
        if b"\x00" in raw[:4096]:
            return "[DENIED] Binary files are not supported.\r\n"

        text = raw.decode("utf-8", errors="replace")
        if not text.endswith("\n"):
            text += "\n"
        return self._truncate(text.replace("\n", "\r\n"))

    async def _cmd_atlas(self, args: list[str]) -> str:
        if not args:
            return "Usage: atlas <checks|scans|health>\r\n"

        subcommand = args[0].lower()
        if subcommand == "checks":
            if len(args) != 1:
                return "[DENIED] Usage: atlas checks\r\n"
            return await asyncio.to_thread(self._atlas_checks)
        if subcommand == "scans":
            if len(args) != 1:
                return "[DENIED] Usage: atlas scans\r\n"
            return await asyncio.to_thread(self._atlas_scans)
        if subcommand == "health":
            if len(args) != 1:
                return "[DENIED] Usage: atlas health\r\n"
            return "status: healthy\r\nservice: atlas-api\r\nmode: restricted-terminal\r\n"
        return f"[DENIED] Unknown atlas command: {subcommand}\r\n"

    def _atlas_checks(self) -> str:
        registry = CheckRegistry()
        checks = registry.get_all_metadata()
        lines = ["ID                        Severity  Category", "-" * 56]
        for check in sorted(checks, key=lambda item: item["id"]):
            check_id = check["id"][:24].ljust(24)
            severity = check["severity"].upper().ljust(8)
            category = check.get("category", "generic")
            lines.append(f"{check_id}  {severity}  {category}")
        return self._truncate("\r\n".join(lines) + "\r\n")

    def _atlas_scans(self) -> str:
        db = get_db()
        sessions = db.list_scan_sessions(limit=20)
        if not sessions:
            return "No scan sessions found.\r\n"

        lines = ["ID       Status     Phase        Target", "-" * 78]
        for session in sessions:
            lines.append(
                f"{session.id:<8} {session.status[:10]:<10} "
                f"{session.phase[:12]:<12} {session.target[:40]}"
            )
        return self._truncate("\r\n".join(lines) + "\r\n")

    def _truncate(self, text: str) -> str:
        limit = self.config.terminal_output_limit_chars
        if len(text) <= limit:
            return text
        return text[:limit] + "\r\n[OUTPUT TRUNCATED]\r\n"


@router.websocket("/ws")
async def terminal_ws(websocket: WebSocket, token: str = Query(...)):
    """
    WebSocket endpoint for restricted terminal sessions.

    Expected client message format:
        {"type":"exec","command":"atlas checks"}
    """
    await websocket.accept()
    config = get_config()

    if not config.enable_web_terminal:
        await websocket.send_text(
            "\r\n[ACCESS DENIED] Web terminal is disabled by server policy.\r\n"
        )
        await websocket.close(code=4003, reason="Terminal disabled")
        return

    if config.web_terminal_mode != "safe":
        await websocket.send_text(
            "\r\n[ACCESS DENIED] Unsafe terminal modes are blocked in this build.\r\n"
        )
        await websocket.close(code=4003, reason="Unsafe mode blocked")
        return

    user = await authenticate_ws(token)
    if not user:
        await websocket.send_text(
            "\r\n[ACCESS DENIED] Terminal requires a valid admin/pentester session.\r\n"
        )
        await websocket.close(code=4003, reason="Unauthorized")
        return

    logger.info("Restricted terminal session opened for %s (%s)", user["username"], user["role"])
    session = RestrictedTerminalSession(user)

    await websocket.send_text(session.banner())
    await websocket.send_text(session.prompt())

    try:
        while True:
            message = await websocket.receive_text()

            try:
                payload = json.loads(message)
            except json.JSONDecodeError:
                await websocket.send_text(
                    "\r\n[ERROR] Unsupported client payload. Please refresh your dashboard.\r\n"
                )
                await websocket.send_text(session.prompt())
                continue

            msg_type = str(payload.get("type", "")).lower()
            if msg_type == "resize":
                continue
            if msg_type != "exec":
                await websocket.send_text("\r\n[ERROR] Unsupported terminal message type.\r\n")
                await websocket.send_text(session.prompt())
                continue

            command = str(payload.get("command", ""))
            output, should_close = await session.execute(command)
            if output:
                await websocket.send_text(output)

            if should_close:
                await websocket.close(code=1000)
                break

            await websocket.send_text(session.prompt())

    except WebSocketDisconnect:
        logger.info("Restricted terminal WS disconnected for %s", user["username"])
    except Exception:
        logger.exception("Restricted terminal session crashed")
    finally:
        logger.info("Restricted terminal session closed for %s", user["username"])
