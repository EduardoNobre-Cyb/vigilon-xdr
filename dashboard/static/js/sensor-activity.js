let selectedSensorId = null;
let sensorPollInterval = null;

function switchLogsTab(tab, btn) {
    document.querySelectorAll('.logs-tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.logs-tab-content').forEach(c => c.classList.remove('active'));
    btn.classList.add('active');
    document.getElementById('logs-tab-' + tab).classList.add('active');

    if (tab === 'sensor') {
        loadSensorList();
    }
}

function loadSensorList() {
    authFetch("/api/edr-agents")
        .then(r => r.json())
        .then(data => {
            const container = document.getElementById("sensor-list-container");
            const agents = [...(data.windows || []), ...(data.linux || [])];

            if (agents.length === 0) {
                container.innerHTML = '<p class="no-data">No sensors registered</p>';
                return;
            }

            container.innerHTML = agents.map(agent => {
                const isOnline = agent.is_online || agent.status === "online";
                const osIcon = agent.os_type === "windows" ? "windows" : "linux";
                const activeClass = agent.agent_id === selectedSensorId ? " active" : "";

                return `
                    <div class="sensor-item${activeClass}" onclick="selectSensor('${agent.agent_id}', '${agent.hostname}', '${agent.os_type}')">
                        <span class="sensor-os-icon" data-icon="${osIcon}"></span>
                        <span class="sensor-name">${agent.hostname}</span>
                        <span class="sensor-status-dot ${isOnline ? 'online' : 'offline'}"></span>
                    </div>
                `;
            }).join('');

            container.querySelectorAll('[data-icon]').forEach(el => {
                const svg = window.ICONS[el.dataset.icon];
                if (svg) el.innerHTML = svg;
            });
        })
        .catch(() => {
            document.getElementById("sensor-list-container").innerHTML = '<p class="no-data">Could not load sensors</p>';
        });
}

function selectSensor(agentId, hostname, osType) {
    selectedSensorId = agentId;

    document.querySelectorAll('.sensor-item').forEach(el => el.classList.remove('active'));
    event.currentTarget.classList.add('active');

    const header = document.getElementById("sensor-feed-header");
    header.style.display = "flex";
    document.getElementById("sensor-feed-hostname").textContent = hostname;
    const shortId = agentId.substring(0, 8);
    document.getElementById("sensor-feed-os").textContent =  "· " + osType + " · " + shortId;

    loadSensorTelemetry(agentId);

    if (sensorPollInterval) clearInterval(sensorPollInterval);
    sensorPollInterval = setInterval(() => loadSensorTelemetry(agentId), 5000);
}

function loadSensorTelemetry(agentId) {
  authFetch(`/api/edr-agents/${agentId}/telemetry?limit=50`)
    .then(r => r.json())
    .then(events => {
      const body = document.getElementById("sensor-feed-body");

      if (!Array.isArray(events) || events.length === 0) {
        body.innerHTML = '<p class="no-data" style="padding:20px;">No telemetry events yet</p>';
        return;
      }

      const shouldAutoScroll = body.scrollTop + body.clientHeight >= body.scrollHeight - 50;
      body.innerHTML = events.slice().reverse().map(ev => {
        const time = new Date(ev.timestamp).toLocaleTimeString('en-GB', {
          hour: '2-digit', minute: '2-digit', second: '2-digit'
        });

        const type = (ev.event_type || "").toLowerCase();
        const badgeLetter = type === "process" ? "P"
                          : type === "file" ? "F"
                          : type === "network" ? "N"
                          : type === "registry" ? "R"
                          : type === "memory" ? "M"
                          : "?";
        const badgeClass = type === "process" ? "process"
                         : type === "file" ? "file"
                         : type === "network" ? "network"
                         : type === "registry" ? "registry"
                         : type === "memory" ? "memory"
                         : "process";

        const desc = formatTelemetryDesc(ev);
        const score = getTelemetryScore(ev);
        const isAlert = score >= 0.7;
        const scoreText = score > 0 ? score.toFixed(2) : "";
        const alertLabel = isAlert ? " ALERT" : "";

        return `
          <div class="telemetry-row">
            <span class="telemetry-time">${time}</span>
            <span class="telemetry-badge ${badgeClass}">${badgeLetter}</span>
            <span class="telemetry-desc">${desc}</span>
            <span class="telemetry-score ${isAlert ? 'alert' : 'normal'}">${scoreText}${alertLabel}</span>
          </div>
        `;
      }).join('');
      if (shouldAutoScroll) body.scrollTop = body.scrollHeight;
    })
    .catch(() => {
      document.getElementById("sensor-feed-body").innerHTML =
        '<p class="no-data" style="padding:20px;">Could not load telemetry</p>';
    });
}

function formatTelemetryDesc(ev) {
    const data = ev.data || {};
    const inner = data.data || data;
    const type = (ev.event_type || "").toLowerCase();

    if (type === "process") {
        const name = inner.process_name || inner.name || "unknown";
        const cmd = inner.command_line || inner.cmdline || "";
        if (cmd) {
            const short = cmd.length > 60 ? cmd.substring(0, 60) + "..." : cmd;
            return escapeHtml(`Pulse: ${name} ${short}`);
        }
        return escapeHtml(`Pulse: ${name}`);
    }

    if (type === "file") {
        const path = inner.file_path || inner.path || "";
        const subtype = ev.event_subtype || "";
        const info = inner.file_type ? `, ${inner.file_type}` : "";
        const packed = inner.packer ? `, ${inner.packer} packed`: "";
        if (path) {
            const short = path.length < 50 ? "..." + path.slice(-50) : path;
            return escapeHtml(`Spectra: ${short}${info}${packed}`);
        }
        return escapeHtml(subtype || "file event");
    }

    if (type === "network") {
        const proc = inner.process_name || "";
        const dst = inner.dest_ip || inner.remote_host || "";
        const port = inner.dest_port || inner.remote_port || "";
        if (dst) {
            return escapeHtml(`Beacon: ${proc} → ${dst}:${port}`);
        }
        return escapeHtml(`Beacon: ${proc || "network event"}`);
    }

    if (type === "memory") {
        const proc = inner.process_name || "unknown";
        const pid = inner.pid || "";
        const base = inner.region_base || "";
        const size = inner.region_size || "";
        const backing = inner.backing_file || "";
        const sizeKB = size ? ` ${(size / 1024).toFixed(0)}KB` : "";
        const backShort = backing && backing !== "none (private)" ? ` [${backing.split("\\").pop()}]` : "";
        return escapeHtml(`Memory: ${proc} PID=${pid} RWX at ${base}${sizeKB}${backShort}`);
    }

    return escapeHtml(ev.event_subtype || ev.event_type || "event");
}

function getTelemetryScore(ev) {
    if (ev.malware_confidence != null && ev.malware_confidence > 0) return ev.malware_confidence;
    if (ev.network_risk_score != null && ev.network_risk_score > 0) return ev.network_risk_Score;
    const data = ev.data || {};
    if (data.ml_score != null) return data.ml_score;
    return 0;
}

function escapeHtml(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}