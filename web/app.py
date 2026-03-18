"""Phantom Web Dashboard — Flask + SocketIO."""

import os
import sys
import json
import threading
from pathlib import Path

from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO
from flask_cors import CORS

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOGS_DIR = PROJECT_ROOT / "logs"

app = Flask(__name__)
app.config["SECRET_KEY"] = "phantom-dashboard-key"
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Track running mission
_mission_thread = None
_mission_stop = threading.Event()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/sessions")
def list_sessions():
    """List all session directories."""
    sessions = []
    if LOGS_DIR.exists():
        for d in sorted(LOGS_DIR.iterdir(), reverse=True):
            if d.is_dir() and d.name != "temp":
                files = [f.name for f in d.iterdir() if f.is_file()]
                has_report = any("report" in f for f in files)
                has_state = "state.json" in files
                sessions.append({
                    "id": d.name,
                    "files": files,
                    "has_report": has_report,
                    "has_state": has_state,
                    "file_count": len(files),
                })
    return jsonify(sessions)


@app.route("/api/sessions/<session_id>")
def session_detail(session_id):
    """Get details of a specific session."""
    session_dir = LOGS_DIR / session_id
    if not session_dir.is_dir():
        return jsonify({"error": "Session not found"}), 404

    files = []
    for f in sorted(session_dir.iterdir()):
        if f.is_file():
            files.append({
                "name": f.name,
                "size": f.stat().st_size,
                "type": f.suffix,
            })

    state = None
    state_path = session_dir / "state.json"
    if state_path.exists():
        try:
            with open(state_path) as f:
                raw = json.load(f)
            state = {"turn": raw.get("turn", 0), "message_count": len(raw.get("messages", []))}
        except Exception:
            pass

    return jsonify({"id": session_id, "files": files, "state": state})


@app.route("/api/sessions/<session_id>/logs/<path:filename>")
def read_log(session_id, filename):
    """Read a log file from a session."""
    file_path = (LOGS_DIR / session_id / filename).resolve()
    if not str(file_path).startswith(str(LOGS_DIR.resolve())):
        return jsonify({"error": "Access denied"}), 403
    if not file_path.exists():
        return jsonify({"error": "File not found"}), 404

    content = file_path.read_text(encoding="utf-8", errors="replace")
    return jsonify({"filename": filename, "content": content[:50000]})


@app.route("/api/sessions/<session_id>/report")
def get_report(session_id):
    """Get the latest HTML report from a session."""
    session_dir = LOGS_DIR / session_id
    reports = sorted(session_dir.glob("report_*.html"), reverse=True)
    if not reports:
        return jsonify({"error": "No report found"}), 404
    return send_file(reports[0])


@app.route("/report/<session_id>")
def view_report(session_id):
    return render_template("report.html", session_id=session_id)


@app.route("/api/missions/start", methods=["POST"])
def start_mission():
    """Start a new mission in a background thread."""
    global _mission_thread
    if _mission_thread and _mission_thread.is_alive():
        return jsonify({"error": "A mission is already running"}), 409

    _mission_stop.clear()
    data = request.json or {}

    def run_mission():
        socketio.emit("mission_status", {"status": "running"})
        try:
            # Import and run the agent
            sys.path.insert(0, str(PROJECT_ROOT / "agent"))
            os.chdir(PROJECT_ROOT)

            import yaml
            with open(PROJECT_ROOT / "config.yaml") as f:
                config = yaml.safe_load(f)

            from tools.logs_helper import init_session
            session_dir = init_session()
            socketio.emit("agent_output", {"text": f"Session: {session_dir}"})

            from agent_client import AgentClient
            client = AgentClient(config=config)

            with open(PROJECT_ROOT / "prompts" / "system_prompt.txt") as f:
                system_prompt = f.read()

            scope_path = PROJECT_ROOT / config.get("scope_file", "scopes/current_scope.md")
            scope = scope_path.read_text() if scope_path.exists() else ""

            messages = [{
                "role": "user",
                "content": f"Authorized scope:\n{scope}\n\nSTART THE MISSION IN AUTONOMOUS MODE.",
            }]

            for turn in range(config.get("max_autonomous_turns", 50)):
                if _mission_stop.is_set():
                    socketio.emit("agent_output", {"text": "Mission stopped by user."})
                    break

                messages = client.think(messages=messages, system_prompt=system_prompt)
                client.save_state(messages, turn, session_dir)

                last = next((m for m in reversed(messages) if m["role"] == "assistant"), None)
                if last:
                    content = last["content"]
                    if isinstance(content, list):
                        for block in content:
                            if block.get("type") == "text":
                                socketio.emit("agent_output", {"text": block["text"]})
                            elif block.get("type") == "tool_use":
                                socketio.emit("tool_start", {"name": block["name"], "input": block["input"]})

                    # Check tool results
                    tool_msg = next((m for m in reversed(messages)
                                    if m["role"] == "user" and isinstance(m.get("content"), list)), None)
                    if tool_msg:
                        for block in tool_msg["content"]:
                            if block.get("type") == "tool_result":
                                socketio.emit("tool_result", {
                                    "id": block["tool_use_id"],
                                    "content": str(block["content"])[:500],
                                })

                    text = " ".join(b.get("text", "") for b in content if isinstance(content, list) and b.get("type") == "text") if isinstance(content, list) else str(content)
                    if "=== MISSION COMPLETE ===" in text:
                        socketio.emit("mission_complete", {"session": session_dir})
                        return

            socketio.emit("mission_complete", {"session": session_dir})

        except Exception as e:
            socketio.emit("mission_error", {"error": str(e)})

    _mission_thread = threading.Thread(target=run_mission, daemon=True)
    _mission_thread.start()
    return jsonify({"status": "started"})


@app.route("/api/missions/stop", methods=["POST"])
def stop_mission():
    _mission_stop.set()
    return jsonify({"status": "stopping"})


@socketio.on("connect")
def on_connect():
    socketio.emit("connected", {"status": "ok"})


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
