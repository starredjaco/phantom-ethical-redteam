"""Session management and logging infrastructure."""

import os
import glob
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


def init_session() -> str:
    """Create a timestamped session directory under logs/ and store it in env."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    session_dir = os.path.join("logs", ts)
    os.makedirs(session_dir, exist_ok=True)
    os.environ["PHANTOM_SESSION_DIR"] = session_dir
    logger.info("Session initialized: %s", session_dir)
    return session_dir


def log_path(filename: str) -> str:
    """Return a session-scoped path under logs/<session>/<filename>."""
    session_dir = os.environ.get("PHANTOM_SESSION_DIR", "logs")
    path = os.path.join(session_dir, filename)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    return path


def find_latest(filename: str) -> str | None:
    """Search for filename in current session, then all sessions (newest first)."""
    current = log_path(filename)
    if os.path.exists(current):
        return current

    pattern = os.path.join("logs", "*", filename)
    matches = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    if matches:
        return matches[0]

    root = os.path.join("logs", filename)
    return root if os.path.exists(root) else None


def get_session_dir() -> str:
    """Return the current session directory."""
    return os.environ.get("PHANTOM_SESSION_DIR", "logs")
