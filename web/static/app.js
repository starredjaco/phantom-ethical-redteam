// Phantom Dashboard — Frontend JS

const socket = io();
let toolTimeline = [];
let findings = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

// --- WebSocket ---
socket.on("connect", () => {
    setStatus("Connected", true);
});

socket.on("disconnect", () => {
    setStatus("Disconnected", false);
});

socket.on("agent_output", (data) => {
    addTerminalLine(data.text, "agent");
    parseFindingsFromText(data.text);
});

socket.on("tool_start", (data) => {
    addTerminalLine(`[TOOL] ${data.name}(${JSON.stringify(data.input).slice(0, 100)})`, "tool");
    addTimelineItem(data.name, "running");
});

socket.on("tool_result", (data) => {
    addTerminalLine(`[RESULT] ${data.content.slice(0, 300)}`, "result");
    updateTimelineItem(data.id, "done");
});

socket.on("mission_complete", (data) => {
    addTerminalLine("=== MISSION COMPLETE ===", "system");
    document.getElementById("btn-launch").disabled = false;
    document.getElementById("btn-stop").disabled = true;
    loadSessions();
});

socket.on("mission_error", (data) => {
    addTerminalLine(`[ERROR] ${data.error}`, "error");
    document.getElementById("btn-launch").disabled = false;
    document.getElementById("btn-stop").disabled = true;
});

// --- UI Functions ---
function setStatus(text, connected) {
    const el = document.getElementById("connection-status");
    el.textContent = text;
    el.className = "status" + (connected ? " connected" : "");
}

function addTerminalLine(text, type) {
    const body = document.getElementById("terminal-body");
    const line = document.createElement("div");
    line.className = `terminal-line ${type || ""}`;
    line.textContent = text;
    body.appendChild(line);
    body.scrollTop = body.scrollHeight;
}

function clearTerminal() {
    document.getElementById("terminal-body").innerHTML = "";
}

function addTimelineItem(name, status) {
    const bar = document.getElementById("timeline-bar");
    const item = document.createElement("span");
    item.className = `timeline-item ${status}`;
    item.textContent = name;
    item.id = `tl-${name}-${Date.now()}`;
    bar.appendChild(item);
    toolTimeline.push(item);
}

function updateTimelineItem(id, status) {
    if (toolTimeline.length > 0) {
        const last = toolTimeline[toolTimeline.length - 1];
        last.className = `timeline-item ${status}`;
    }
}

function updateFindings() {
    for (const sev of ["critical", "high", "medium", "low", "info"]) {
        document.getElementById(`count-${sev}`).textContent = `${findings[sev]} ${sev.charAt(0).toUpperCase() + sev.slice(1)}`;
    }
}

function parseFindingsFromText(text) {
    const patterns = {
        critical: /\[CRITICAL\]/gi,
        high: /\[HIGH\]/gi,
        medium: /\[MEDIUM\]/gi,
        low: /\[LOW\]/gi,
        info: /\[INFO\]/gi,
    };
    let changed = false;
    for (const [sev, re] of Object.entries(patterns)) {
        const matches = text.match(re);
        if (matches) {
            findings[sev] += matches.length;
            changed = true;
        }
    }
    if (changed) updateFindings();
}

// --- Mission Control ---
function startMission() {
    const scope = document.getElementById("scope-input").value;
    if (!scope) {
        addTerminalLine("Please enter a target scope first.", "error");
        return;
    }

    document.getElementById("btn-launch").disabled = true;
    document.getElementById("btn-stop").disabled = false;
    findings = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    updateFindings();
    document.getElementById("timeline-bar").innerHTML = "";
    toolTimeline = [];

    addTerminalLine(`Starting mission against: ${scope}`, "system");

    fetch("/api/missions/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scope, provider: document.getElementById("provider-select").value }),
    })
    .then(r => r.json())
    .then(data => {
        if (data.error) addTerminalLine(`Error: ${data.error}`, "error");
    })
    .catch(err => addTerminalLine(`Error: ${err}`, "error"));
}

function stopMission() {
    fetch("/api/missions/stop", { method: "POST" })
    .then(() => addTerminalLine("Stop requested...", "system"));
}

// --- Session Management ---
function loadSessions() {
    fetch("/api/sessions")
    .then(r => r.json())
    .then(sessions => {
        const list = document.getElementById("session-list");
        list.innerHTML = "";
        sessions.forEach(s => {
            const item = document.createElement("div");
            item.className = "session-item";
            item.innerHTML = `
                <div class="session-id">${s.id}</div>
                <div class="session-meta">${s.file_count} files ${s.has_report ? "| Report" : ""}</div>
            `;
            item.onclick = () => loadSession(s.id);
            list.appendChild(item);
        });
    });
}

function loadSession(sessionId) {
    // Highlight active
    document.querySelectorAll(".session-item").forEach(el => el.classList.remove("active"));
    event.currentTarget.classList.add("active");

    fetch(`/api/sessions/${sessionId}`)
    .then(r => r.json())
    .then(data => {
        clearTerminal();
        addTerminalLine(`Session: ${sessionId}`, "system");
        data.files.forEach(f => {
            addTerminalLine(`  ${f.name} (${f.size} bytes)`, "system");
        });
        if (data.state) {
            addTerminalLine(`  Turn: ${data.state.turn} | Messages: ${data.state.message_count}`, "system");
        }

        // Load agent.log if exists
        const logFile = data.files.find(f => f.name === "agent.log");
        if (logFile) {
            fetch(`/api/sessions/${sessionId}/logs/agent.log`)
            .then(r => r.json())
            .then(log => {
                addTerminalLine("--- Agent Log ---", "system");
                log.content.split("\n").slice(-50).forEach(line => {
                    addTerminalLine(line, "agent");
                });
            });
        }
    });
}

// --- Init ---
loadSessions();
