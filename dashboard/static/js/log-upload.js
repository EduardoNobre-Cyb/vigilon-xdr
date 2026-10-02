// Moved out of templates/dashboard.html (was an inline <script>). Loaded as a classic
// script so its functions stay global for the onclick="..." handlers.
async function handleLogUpload(input) {
  const file = input.files[0];
  if (!file) return;

  const statusDiv = document.getElementById("upload-status");

  // Show uploading state
  statusDiv.style.display = "block";
  statusDiv.style.background = "#1a1f3a";
  statusDiv.style.border = "1px solid #00ff00";
  statusDiv.style.color = "#00ff00";
  statusDiv.textContent = `Uploading ${file.name}...`;

  // Build FormData (this is how you send files via fetch)
  const formData = new FormData();
  formData.append("logfile", file); // 'logfile' must match request.files["logfile"] in Flask

  try {
    const token = localStorage.getItem("auth_token");
    const response = await fetch("/upload_log", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        // Do NOT set Content-Type — browser sets it automatically for FormData
      },
      body: formData,
    });

    const data = await response.json();

    if (response.ok) {
      statusDiv.style.borderColor = "#00ff00";
      statusDiv.style.color = "#00ff00";
      statusDiv.textContent = `✅ ${data.message}`;
      // Refresh the logs list to show the newly ingested data
      loadLogs();
    } else {
      statusDiv.style.borderColor = "#ff4444";
      statusDiv.style.color = "#ff4444";
      statusDiv.textContent = `❌ ${data.error || "Upload failed"}`;
    }
  } catch (err) {
    statusDiv.style.borderColor = "#ff4444";
    statusDiv.style.color = "#ff4444";
    statusDiv.textContent = `❌ Network error: ${err.message}`;
  }

  // Clear the input so the same file can be re-uploaded
  input.value = "";

  // Hide status after 5 seconds
  setTimeout(() => {
    statusDiv.style.display = "none";
  }, 5000);
}
let logsEventSource = null;

function updateLineCount() {
  const body = document.getElementById('logs-modal-body');
  const count = document.getElementById('logs-modal-linecount');
  const lines = body.innerHTML.split('\n').length;
  count.textContent = lines + ' line' + (lines !== 1 ? 's' : '');
}

function openLogsModal(agentId, agentName) {
  const modal = document.getElementById('agent-logs-modal');
  const body  = document.getElementById('logs-modal-body');
  const title = document.getElementById('logs-modal-title');
  const count = document.getElementById('logs-modal-linecount');
  title.textContent = agentId + '.log';
  body.innerHTML = '<span style="color:#555;">Loading&hellip;</span>';
  count.textContent = '';
  modal.style.display = 'flex';

  authFetch(`/api/agents/${agentId}/logs?lines=200`)
    .then(r => r.json())
    .then(data => {
      const lines = data.logs || [];
      if (lines.length === 0) {
        body.innerHTML = '<span style="color:#555;">No log entries found. Run the agent first.</span>';
        count.textContent = '0 lines';
        return;
      }
      body.innerHTML = lines.map(line => {
        const escaped = line.replace(/</g, '&lt;').replace(/>/g, '&gt;').trimEnd();
        if (escaped.includes(' ERROR'))   return `<span style="color:#ff4444;">${escaped}</span>`;
        if (escaped.includes(' WARNING')) return `<span style="color:#ffaa00;">${escaped}</span>`;
        return `<span>${escaped}</span>`;
      }).join('\n');
      count.textContent = lines.length + ' line' + (lines.length !== 1 ? 's' : '');
      // Scroll to bottom
      body.scrollTop = body.scrollHeight;
    })
    .catch(err => {
      body.innerHTML = '<span style="color:#ff4444;">[ERROR] Failed to fetch logs. Is the server running?</span>';
    });

  const token = localStorage.getItem("auth_token");
  logsEventSource = new EventSource(`/api/agents/${agentId}/logs/stream?token=${token}`);

  logsEventSource.onmessage = function(event) {
    const body = document.getElementById("logs-modal-body");
    const line = event.data;

    // Check scroll BEFORE appending (scrollHeight hasn't changed yet)
    const isNearBottom = body.scrollHeight - body.scrollTop - body.clientHeight < 150;

    // Colour-coded just like the initial render
    const escaped = line.replace(/</g, "&lt;").replace(/>/g, "&gt;").trimEnd();
    let html;
    if (escaped.includes(" ERROR"))
      html = `<span style="color:#ff4444;">${escaped}</span>`;
    else if (escaped.includes(" WARNING"))
      html = `<span style="color:#ffaa00;">${escaped}</span>`;
    else
      html = `<span>${escaped}</span>`;

    // Append with insertAdjacentHTML — avoids full innerHTML re-parse
    body.insertAdjacentHTML("beforeend", "\n" + html);

    // Auto-scroll on next animation frame so the DOM has updated
    if (isNearBottom) {
      requestAnimationFrame(() => { body.scrollTop = body.scrollHeight; });
    }

    // Update line count
    updateLineCount();
  };

  logsEventSource.onerror = function () {
    // Connection lost - EventSource auto-reconnects, nothing to do
    // Optionally, could show a "Connection lost, retrying..." message if desired

  };
}

function closeLogsModal() {
  // Close SSE connection when modal closes
  if (logsEventSource) {
    logsEventSource.close();
    logsEventSource = null;
  }
  document.getElementById("agent-logs-modal").style.display = "none";
}

// Close on backdrop click
document.getElementById('agent-logs-modal').addEventListener('click', function(e) {
  if (e.target === this) closeLogsModal();
});

// Close on Escape key
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') closeLogsModal();
});
