// Moved out of templates/dashboard.html (was an inline <script>). Loaded as a classic
// script so its functions stay global for the onclick="..." handlers.
function fetchAgentStatus() {
  authFetch("/api/agents/status")
    .then((response) => response.json())
    .then((data) => {
      const container = document.getElementById("agent-status-container");
      container.innerHTML = "";

      data.agents.forEach((agent) => {
        const isRunning = agent.status === "Running";
        const card = document.createElement("div");
        card.className = "agent-card-mgmt";

        const statusClass = isRunning ? "status-running" : "status-stopped";
        const statusText = agent.status;

        let heartbeatHTML = "";
        // API sends the text "No heartbeat detected" when there is none, so check it's a real date
        const hbDate = agent.last_heartbeat ? new Date(agent.last_heartbeat) : null;
        if (hbDate && !isNaN(hbDate)) {
          const hbTime = hbDate.toLocaleTimeString();
          heartbeatHTML = `<p class="agent-heartbeat">Last heartbeat: ${hbTime}</p>`;
        } else {
          heartbeatHTML = `<p class="agent-heartbeat">No heartbeat received</p>`;
        }

        let buttonsHTML = "";
        if (isRunning) {
          buttonsHTML = `
            <button class="btn btn-stop" onclick="agentAction('${agent.id}', 'stop')">Stop</button>
            <button class="btn btn-logs" onclick="openLogsModal('${agent.id}', '${agent.name}')">Logs</button>
          `;
        } else {
          buttonsHTML = `
            <button class="btn btn-start" onclick="agentAction('${agent.id}', 'start')">Start</button>
            <button class="btn btn-logs" onclick="openLogsModal('${agent.id}', '${agent.name}')">Logs</button>
          `;
        }

        card.innerHTML = `
          <h3>${agent.name}</h3>
          <p class="agent-role">${agent.role}</p>
          <div class="agent-status">
            <span class="status-indicator ${statusClass}">●</span>
            <span class="status-text ${statusClass}">${statusText}</span>
          </div>
          ${heartbeatHTML}
          <div class="agent-controls">
            ${buttonsHTML}
          </div>
          <div id="model-review-${agent.id}" style="display:none; margin-top:10px;"></div>
        `;
        container.appendChild(card);

        // Fetch pending models for Vigilon Triage (classifier) and Vigilon Sentinel (hunter)
        if (agent.id === "classifier_001" || agent.id === "hunter_001") {
          fetchPendingModelsForAgent(agent.id);
        }
      });
    })
    .catch((err) => {
      console.error("Failed to fetch agent status:", err);
      const container = document.getElementById("agent-status-container");
      container.innerHTML = '<p class="no-data">Unable to fetch agent status</p>';
    });
}

// Initial fetch + repeat every 5 seconds
fetchAgentStatus();
setInterval(fetchAgentStatus, 5000);

async function agentAction(agentId, action) {
    // Disable the button immediatly to prevent double-clicks
    event.target.disabled = true;
    event.target.textContent = action === 'start' ? "Starting..." : "Stopping...";

    try {
      const response = await authFetch(`/api/agents/${agentId}/${action}`, { method: 'POST' });
      const data = await response.json();

      if (!response.ok) {
        alert(`Error: ${data.error || "Unknown error"}`);
      } else if (action === 'stop') {
        // Refresh immediately so the button flips back without waiting for the next poll
        fetchAgentStatus();
      }
      // Do nothing on success for start - the status will update on the next refresh cycle
    } catch (err) {
      alert(`Failed to ${action} agent: ${err.message}`);
    }

    // Re-enable button (the 5s poll will replace the card anyway)
    event.target.disabled = false;
}

async function fetchPendingModelsForAgent(agentId) {
  try {
    const response = await fetch(
      `/api/models?agent_id=${agentId}&status=pending`,
    );
    const data = await response.json();

    if (data.status !== "success") {
      console.error("Failed to fetch models:", data.message);
      return;
    }

    const pendingModels = data.models;
    const modelReviewSection = document.getElementById(
      `model-review-${agentId}`,
    );

    // If no pending models, keep section hidden
    if (!pendingModels || pendingModels.length === 0) {
      modelReviewSection.style.display = "none";
      return;
    }

    // Pending model exists - show section
    modelReviewSection.style.display = "block";
    const pendingModel = pendingModels[0];

    // Fetch active model for modal comparison
    const activeResponse = await fetch(
      `/api/models?agent_id=${agentId}&status=active`,
    );
    const activeData = await activeResponse.json();
    const activeModel = activeData.models && activeData.models.length > 0 ? activeData.models[0] : null;

    // Populate the notification
    populateModelReviewNotification(
      modelReviewSection,
      agentId,
      activeModel,
      pendingModel,
    );
  } catch (error) {
    console.error(`Error fetching models for ${agentId}:`, error);
  }
}

function populateModelReviewNotification(section, agentId, activeModel, pendingModel) {
  let html = `
    <div style="display: flex; justify-content: space-between; align-items: center; padding: 10px; border-top: 1px solid #00ff00; margin-top: 10px;">
      <div style="color: #00ff00; font-size: 12px; animation: pulse 1.5s infinite;">
        ● New Model Pending: ${pendingModel.version}
      </div>
      <button onclick="showModelComparisonModal('${agentId}', ${pendingModel.id}, ${activeModel ? activeModel.id : "null"})"
              class="btn-review">
        Review
      </button>
    </div>
  `;

  section.innerHTML = html;
}

function showModelComparisonModal(agentId, pendingModelId, activeModelId) {
  // Create modal backdrop
  let modal = document.getElementById(`model-comparison-modal-${agentId}`);
  if (!modal) {
    modal = document.createElement("div");
    modal.id = `model-comparison-modal-${agentId}`;
    modal.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(0, 0, 0, 0.8);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 10000;
    `;
    document.body.appendChild(modal);
  }

  // Populate modal with comparison table
  modal.innerHTML = `
    <div style="background-color: #1a1a1a; border: 2px solid #00ff00; padding: 20px; width: 80%; max-height: 80vh; overflow-y: auto; color: #00ff00; font-family: monospace; display: flex; flex-direction: column; position: relative;">

      <!-- Close Button (X) in Top Right -->
      <button onclick="document.getElementById('model-comparison-modal-${agentId}').style.display='none'"
              style="position: absolute; top: 15px; right: 15px; background: none; border: none; color: #00ff00; font-size: 24px; cursor: pointer; padding: 0; width: 30px; height: 30px; display: flex; align-items: center; justify-content: center; hover: {opacity: 0.8;}">
        ✕
      </button>

      <!-- Header -->
      <div style="margin-bottom: 15px; padding-bottom: 10px; border-bottom: 1px solid #00ff00; padding-right: 40px;">
        <div style="font-size: 16px; font-weight: bold;">Model Comparison: ${agentId}</div>
      </div>

      <!-- Metrics Table -->
      <div id="comparison-table-${agentId}" style="flex: 1; overflow-y: auto; margin-bottom: 15px;">
        Loading comparison data...
      </div>

      <!-- Buttons: Approve (left) | Reject (right) -->
      <div style="display: flex; justify-content: flex-start; gap: 20px; padding-top: 15px; border-top: 1px solid #00ff00;">
        <button onclick="approveModel(${pendingModelId}, '${agentId}')"
                class="btn-approve"
                style="flex: 0 0 auto;">
          ✓ Approve
        </button>
        <button onclick="rejectModel(${pendingModelId}, '${agentId}')"
                class="btn-reject"
                style="margin-left: auto; flex: 0 0 auto;">
          ✕ Reject
        </button>
      </div>
    </div>
  `;

  modal.style.display = "flex";

  // Fetch and populate comparison table
  Promise.all([
    fetch(`/api/models/${pendingModelId}`).then((r) => r.json()),
    activeModelId
      ? fetch(`/api/models/${activeModelId}`).then((r) => r.json())
      : Promise.resolve({ model: null }),
  ])
    .then(([pendingData, activeData]) => {
      const pendingModel = pendingData.model;
      const activeModel = activeData.model;

      let tableHTML = `
      <table style="width: 100%; border-collapse: collapse; font-size: 12px;">
        <tr style="background-color: rgba(0, 255, 0, 0.1); border-bottom: 1px solid #00ff00;">
          <th style="padding: 8px; text-align: left; color: #00ff00;">Metric</th>
          <th style="padding: 8px; text-align: left; color: #888;">${activeModel ? "Current" : "N/A"}</th>
          <th style="padding: 8px; text-align: left; color: #00ff00; font-weight: bold;">New</th>
          <th style="padding: 8px; text-align: center; color: #ffff00;">Change</th>
        </tr>
    `;
        const formatMetric = (value) => {
          if (typeof value === "number" && value < 1)
            return (value * 100).toFixed(1) + "%";
          return value ? value.toFixed(2) : "N/A";
        };

        const diff = (newVal, oldVal) => {
          if (!oldVal || typeof newVal !== "number" || typeof oldVal !== "number")
            return "—";
          const change = ((newVal - oldVal) * 100).toFixed(1);
          const color = change > 0 ? "#00ff00" : change < 0 ? "#ff0000" : "#888";
          return `<span style="color: ${color};">${change > 0 ? "+" : ""}${change}%</span>`;
        }

        // Core metrics
        const metrics = [
          { label: "Accuracy", key: "accuracy" },
          { label: "Macro F1", key: "macro_f1" },
          { label: "Training Duration (s)", key: "training_duration_seconds" },
        ];

        metrics.forEach((metric) => {
          const newVal = pendingModel[metric.key];
          const oldVal = activeModel ? activeModel[metric.key] : null;
          tableHTML += `
          <tr style="border-bottom: 1px solid #333;">
            <td style="padding: 8px; color: #00ff00; font-weight: bold;">${metric.label}</td>
            <td style="padding: 8px; color: #888;">${oldVal !== null ? formatMetric(oldVal) : "N/A"}</td>
            <td style="padding: 8px; color: #00ff00;">${formatMetric(newVal)}</td>
            <td style="padding: 8px; text-align: center;">${diff(newVal, oldVal)}</td>
          </tr>
        `;
        });

        // Per-class recalls
        if (pendingModel.recall_per_class) {
          tableHTML += `
          <tr style="background-color: rgba(0, 255, 0, 0.1); border-bottom: 1px solid #00ff00;">
            <td colspan="4" style="padding: 8px; color: #00ff00; font-weight: bold;">Per-Class Recall</td>
          </tr>
        `;

          for (const [threat, recall] of Object.entries(
            pendingModel.recall_per_class,
          )) {
            const oldRecall = activeModel?.recall_per_class?.[threat] || null;
            tableHTML += `
            <tr style="border-bottom: 1px solid #333;">
              <td style="padding: 8px; color: #888;">└─ ${threat}</td>
              <td style="padding: 8px; color: #888;">${oldRecall ? formatMetric(oldRecall) : "N/A"}</td>
              <td style="padding: 8px; color: #00ff00;">${formatMetric(recall)}</td>
              <td style="padding: 8px; text-align: center;">${diff(recall, oldRecall)}</td>
            </tr>
          `;
          }
        }

        tableHTML += `</table>`;
        document.getElementById(`comparison-table-${agentId}`).innerHTML =
          tableHTML;
    })
    .catch((error) => {
      console.error("Error loading comparison:", error);
      document.getElementById(`comparison-table-${agentId}`).innerHTML =
        `<div style="color: #ff0000;">Error loading comparison data</div>`;
    });
}

async function approveModel(modelId, agentId) {
  if (!confirm("Approve this model?")) return;

  try {
    const response = await fetch(`/api/models/${modelId}/approve`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        analyst_id: getCurrentAnalystId(),
        notes: "Approved via dashboard",
      }),
    });

    const data = await response.json();
    if (data.status === "success") {
      // Modal approved - now show deployment confirmation modal
      showDeploymentConfirmationModal(modelId, agentId);
    } else {
      alert(`Error: ${data.message}`);
    }
  } catch (error) {
    console.error("Error approving:", error);
    alert("Error approving model");
  }
}

function showDeploymentConfirmationModal(modelId, agentId) {
  // Create modal backdrop
  let deployModal = document.getElementById(
    `deploy-confirmation-modal-${agentId}`,
  );
  if (!deployModal) {
    deployModal = document.createElement("div");
    deployModal.id = `deploy-confirmation-modal-${agentId}`;
    document.body.appendChild(deployModal);
  }

  deployModal.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(0, 0, 0, 0.9);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 10001;
  `;

  deployModal.innerHTML = `
    <div style="background-color: #1a1a1a; border: 2px solid #00ff00; padding: 30px; width: 500px; color: #00ff00; font-family: monospace; display: flex; flex-direction: column; gap: 15px; border-radius: 5px;">

      <!-- Header -->
      <div style="font-size: 18px; font-weight: bold; border-bottom: 1px solid #00ff00; padding-bottom: 10px;">
        🚀 Deploy Model
      </div>

      <!-- Message -->
      <div style="font-size: 13px; line-height: 1.6;">
        Model has been <span style="color: #00ff00; font-weight: bold;">✅ APPROVED</span> successfully!
        <br><br>
        Would you like to <span style="color: #ffff00;">deploy</span> this model now?
        <br><br>
        <span style="color: #888; font-size: 11px;">
          (This will immediately switch agents to use the new model)
        </span>
      </div>

      <!-- Buttons: Deploy (green) | Cancel (red) -->
      <div style="display: flex; gap: 10px; justify-content: flex-end; padding-top: 10px; border-top: 1px solid #00ff00;">
        <button 
          onclick="closeDeploymentConfirmation('${agentId}')"
          style="padding: 10px 20px; background-color: #333; color: #ff0000; border: 1px solid #ff0000; cursor: pointer; font-weight: bold; border-radius: 3px; font-family: monospace; font-size: 12px;">
          Cancel
        </button>
        <button 
          onclick="deployModelNow(${modelId}, '${agentId}')"
          style="padding: 10px 20px; background-color: #00ff00; color: #000; border: none; cursor: pointer; font-weight: bold; border-radius: 3px; font-family: monospace; font-size: 12px;">
          Deploy Now
        </button>
      </div>
    </div>
  `;

  deployModal.style.display = "flex";
}

function closeDeploymentConfirmation(agentId) {
  const deployModal = document.getElementById(
    `deploy-confirmation-modal-${agentId}`,
  );
  if (deployModal) {
    deployModal.style.display = "none";
  }

  const comparisonModal = document.getElementById(
    `model-comparison-modal-${agentId}`,
  );
  if (comparisonModal) {
    comparisonModal.style.display = "none";
  }

  fetchAgentStatus(); // Refresh cards
}

async function deployModelNow(modelId, agentId) {
  try {
    const response = await fetch(`/api/models/${modelId}/deploy`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        analyst_id: getCurrentAnalystId(),
      }),
    });

    const data = await response.json();
    if (data.status === "success") {
      // Show success message in modal
      const deployModal = document.getElementById(
        `deploy-confirmation-modal-${agentId}`,
      );
      deployModal.innerHTML = `
        <div style="background-color: #1a1a1a; border: 2px solid #00ff00; padding: 30px; width: 500px; color: #00ff00; font-family: monospace; text-align: center; border-radius: 5px;">
          <div style="font-size: 24px; margin-bottom: 15px;">✅</div>
          <div style="font-size: 16px; font-weight: bold; margin-bottom: 10px;">Model Deployed Successfully!</div>
          <div style="font-size: 12px; color: #888; margin-bottom: 20px;">
            Agents are now using the new model.
            <br><br>
            <span style="color: #00ff00;">Next inference will use updated model</span>
          </div>
          <button 
            onclick="closeDeploymentConfirmation('${agentId}')"
            style="padding: 10px 30px; background-color: #00ff00; color: #000; border: none; cursor: pointer; font-weight: bold; border-radius: 3px; font-family: monospace; font-size: 12px;">
            Close
          </button>
        </div>
      `;

      // Auto-close after 3 seconds
      setTimeout(() => {
        closeDeploymentConfirmation(agentId);
      }, 3000);
    } else {
      // Show error in modal
      const deployModal = document.getElementById(
        `deploy-confirmation-modal-${agentId}`,
      );
      deployModal.innerHTML = `
        <div style="background-color: #1a1a1a; border: 2px solid #ff0000; padding: 30px; width: 500px; color: #ff0000; font-family: monospace; text-align: center; border-radius: 5px;">
          <div style="font-size: 24px; margin-bottom: 15px;">❌</div>
          <div style="font-size: 16px; font-weight: bold; margin-bottom: 10px;">Deployment Failed</div>
          <div style="font-size: 12px; margin-bottom: 20px;">
            ${data.message || "Unknown error"}
          </div>
          <button 
            onclick="closeDeploymentConfirmation('${agentId}')"
            style="padding: 10px 30px; background-color: #ff0000; color: #000; border: none; cursor: pointer; font-weight: bold; border-radius: 3px; font-family: monospace; font-size: 12px;">
            Close
          </button>
        </div>
      `;
    }
  } catch (error) {
    console.error("Error deploying:", error);
    const deployModal = document.getElementById(
      `deploy-confirmation-modal-${agentId}`,
    );
    deployModal.innerHTML = `
      <div style="background-color: #1a1a1a; border: 2px solid #ff0000; padding: 30px; width: 500px; color: #ff0000; font-family: monospace; text-align: center; border-radius: 5px;">
        <div style="font-size: 24px; margin-bottom: 15px;">❌</div>
        <div style="font-size: 16px; font-weight: bold; margin-bottom: 10px;">Error</div>
        <div style="font-size: 12px; margin-bottom: 20px;">
          ${error.message || "Failed to deploy model"}
        </div>
        <button 
          onclick="closeDeploymentConfirmation('${agentId}')"
          style="padding: 10px 30px; background-color: #ff0000; color: #000; border: none; cursor: pointer; font-weight: bold; border-radius: 3px; font-family: monospace; font-size: 12px;">
          Close
        </button>
      </div>
    `;
  }
}

async function rejectModel(modelId, agentId) {
  if (!confirm("Reject this model?")) return;

  try {
    const response = await fetch(`/api/models/${modelId}/reject`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        analyst_id: getCurrentAnalystId(),
        reason: "Rejected via dashboard",
      }),
    });

    const data = await response.json();
    if (data.status === "success") {
      alert("✅ Model rejected!");
      document.getElementById(
        `model-comparison-modal-${agentId}`,
      ).style.display = "none";

      // Refresh agent status and pending models
      fetchAgentStatus();

      // Also explicitly refresh pending models after a brief delay
      setTimeout(() => {
        fetchPendingModelsForAgent(agentId);
      }, 500);
    } else {
      alert(`Error: ${data.message}`);
    }
  } catch (error) {
    console.error("Error rejecting:", error);
    alert("Error rejecting model");
  }
}

function decodeJWT(token) {
  try {
    const base64Url = token.split('.')[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(atob(base64).split('').map((c) => {
      return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(''));
    return JSON.parse(jsonPayload);
  } catch (error) {
    console.error("Error decoding JWT:", error);
    return null;
  }
}

function getCurrentAnalystId() {
  const id = sessionStorage.getItem("analyst_id");
  if (id) {
    return parseInt(id, 10);
  }

  // Try to extract from JWT token
  const token = localStorage.getItem("auth_token");
  if (token) {
    const decoded = decodeJWT(token);
    if (decoded && decoded.sub) {
      const analyst_id = parseInt(decoded.sub, 10);
      sessionStorage.setItem("analyst_id", analyst_id.toString());
      return analyst_id;
    }
  }

  // No analyst_id available
  console.error("No analyst_id found in token or storage");
  return null;
}

async function initializeCurrentUser() {
  try {
    const response = await fetch("/api/auth/me");
    if (response.ok) {
      const data = await response.json();
      if (data.analyst_id) {
        sessionStorage.setItem("analyst_id", data.analyst_id.toString());
      }
    } else {
      // Fallback: try to extract from JWT token
      const token = localStorage.getItem("auth_token");
      if (token) {
        const decoded = decodeJWT(token);
        if (decoded && decoded.sub) {
          sessionStorage.setItem("analyst_id", decoded.sub);
        }
      }
    }
  } catch (error) {
    console.error("Error fetching current user:", error);
  }
}

// Initialize when DOM is ready
document.addEventListener("DOMContentLoaded", initializeCurrentUser);

// EDR Agent Functions
async function refreshEDRAgents() {
  try {
    const response = await authFetch("/api/edr-agents");
    if (!response.ok) throw new Error(`API Error: ${response.status}`);

    const data = await response.json();
    updateEDRAgentCards(data);

    const summaryRes = await authFetch("/api/edr-agents/summary?hours=24&min_confidence=0.45");
    if (summaryRes.ok) {
      const summary = await summaryRes.json();
      document.getElementById("summary-events").textContent = summary.total_events ?? 0;
      document.getElementById("summary-high-conf").textContent = summary.high_conf_detections ?? 0;
    }

    // Fetch detections
    const detectRes = await authFetch("/api/edr-agents/detections?limit=200&min_confidence=0.45");
    if (detectRes.ok) {
      const detections = await detectRes.json();
      allDetectionResults = detections;
      renderDetectionPage(currentDetectionPage);
    }
  } catch (error) {
    console.error("Failed to refresh EDR agents:", error);
    showEDRMessage(`Error: ${error.message}`, "error");
  }
}

function updateEDRAgentCards(data) {
  const windowsAgents = data.windows || [];
  const linuxAgents = data.linux || [];

  // Windows Counts
  const winOnline = windowsAgents.filter(a => a.is_online).length;
  const winOffline = windowsAgents.filter(a => !a.is_online).length;

  document.getElementById("win-online").textContent = winOnline;
  document.getElementById("win-offline").textContent = winOffline;

  const windowsHTML = windowsAgents.map(agent => `
    <li class="${agent.is_online ? "online" : ""}">
      <span>
        <strong>${agent.hostname}</strong><br>
        <small>${agent.agent_id.substring(0, 8)}</small>
        </span>
        <span class="agent-status">
          ${agent.is_online ? "🟢 Online" : "🔴 Offline"}
        </span>
    </li>
    `).join("");

    document.getElementById("windows-list").innerHTML = windowsHTML || "<li>No Windows agents</li>";

  // Linux Counts
  const linuxOnline = linuxAgents.filter(a => a.is_online).length;
  const linuxOffline = linuxAgents.filter(a => !a.is_online).length;

  document.getElementById("linux-online").textContent = linuxOnline;
  document.getElementById("linux-offline").textContent = linuxOffline;

  const linuxHTML = linuxAgents.map(agent => `
    <li class="${agent.is_online ? "online" : ""}">
      <span>
        <strong>${agent.hostname}</strong><br>
        <small>${agent.agent_id.substring(0, 8)}</small>
      </span>
      <span class="agent-status">
        ${agent.is_online ? "🟢 Online" : "🔴 Offline"}
      </span>
    </li>
  `).join("");

  document.getElementById("linux-list").innerHTML = linuxHTML || "<li>No Linux agents</li>";

}

const detectionsPerPage = 8;
let currentDetectionPage = 1;
let allDetectionResults = [];

function renderDetectionPage(page) {
  const detections = allDetectionResults || [];
  const totalPages = Math.max(1, Math.ceil(detections.length / detectionsPerPage));
  currentDetectionPage = Math.min(Math.max(page, 1), totalPages);

  const startIndex = (currentDetectionPage - 1) * detectionsPerPage;
  const pageItems = detections.slice(startIndex, startIndex + detectionsPerPage);

  const pageInfo = document.getElementById("detection-page-info");
  const prevBtn = document.getElementById("btn-detection-prev");
  const nextBtn = document.getElementById("btn-detection-next");

  if (pageInfo) pageInfo.textContent = `${currentDetectionPage}/${totalPages}`;
  if (prevBtn) prevBtn.disabled = currentDetectionPage <= 1;
  if (nextBtn) nextBtn.disabled = currentDetectionPage >= totalPages;

  if (!pageItems || pageItems.length === 0) {
    document.getElementById("detection-tbody").innerHTML = '<tr class="loading-row"><td colspan="5">No high-confidence detections</td></tr>';
    return;
  }

  const html = pageItems.map(d => {
    const dt = new Date(d.timestamp);
    const time = Number.isNaN(dt.getTime())
      ? "-"
      : `${dt.toLocaleDateString()}<br><small style="color:#888;">${dt.toLocaleTimeString()}</small>`;
    const sourceLabel = d.source || "EDR Telemetry";
    const detailsLabel = d.data.name || d.data.process_name || '-';
    const osVersion = d.os_version && d.os_version !== "undefined" ? d.os_version : "-";
    const eventTypeRaw = String(d.event_type || "").toLowerCase();
    const eventTypeShort = eventTypeRaw === "process" ? "P" : eventTypeRaw === "network" ? "N" : "?";
    const eventTypeTitle = eventTypeRaw || "unknown";

    return `
        <tr>
          <td>${d.hostname}</td>
          <td>${osVersion}</td>
          <td>
            <span class="edr-event-badge" title="${eventTypeTitle}">${eventTypeShort}</span>
          </td>
          <td>${time}</td>
          <td>${detailsLabel}<br><small style="color:#888;">${sourceLabel}</small></td>
        </tr>
    `;
  }).join("");

  document.getElementById("detection-tbody").innerHTML = html;

}

function changeDetectionPage(delta) {
  renderDetectionPage(currentDetectionPage + delta);
}

let edrActionsState = {
  agents: [],
  selectedAgentId: null,
  selectedOsType: null,
  telemetry: [],
  telemetryCategory: "All",
  selectedTelemetryIndex: null,
  agentActions: [],
};

function escapeHTML(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function openEDRActionsModal(osType = null) {
  const modal = document.getElementById("edr-actions-modal");
  modal.style.display = "flex";
  edrActionsState.selectedOsType = osType;
  edrActionsState.selectedAgentId = null;
  edrActionsState.telemetry = [];
  edrActionsState.telemetryCategory = "All";
  edrActionsState.selectedTelemetryIndex = null;
  edrActionsState.agentActions = [];
  document.getElementById("edr-actions-content").innerHTML = '<div style="padding:16px; border:1px dashed #1f3b23; border-radius:6px; color:#64748b;">Loading agents...</div>';
  document.getElementById("edr-actions-agent-list").innerHTML = '<div style="color:#64748b; font-size:12px;">Loading online agents...</div>';
  document.getElementById("edr-actions-telemetry-list").innerHTML = '<div style="color:#64748b; font-size:12px;">Select an online agent.</div>';
  document.getElementById("edr-actions-telemetry-count").textContent = "0 events";
  updateTelemetryCategoryControls();
  loadEDRActionsModalData();
}

function closeEDRActionsModal() {
  document.getElementById("edr-actions-modal").style.display = "none";
}

async function loadEDRActionsModalData() {
  try {
    const response = await authFetch("/api/edr-agents");
    if (!response.ok) throw new Error(`API Error: ${response.status}`);

    const data = await response.json();
    const agents = [...(data.windows || []), ...(data.linux || [])].filter((agent) => agent.is_online);
    edrActionsState.agents = agents;

    document.getElementById("edr-actions-agent-count").textContent = `${agents.length} online`;

    if (agents.length === 0) {
      document.getElementById("edr-actions-agent-list").innerHTML = '<div style="color:#64748b; font-size:12px;">No online agents available.</div>';
      document.getElementById("edr-actions-telemetry-list").innerHTML = '<div style="color:#64748b; font-size:12px;">No online agents are currently connected.</div>';
      document.getElementById("edr-actions-content").innerHTML = '<div style="padding:16px; border:1px dashed #1f3b23; border-radius:6px; color:#64748b;">No online agents are currently connected.</div>';
      return;
    }

    document.getElementById("edr-actions-agent-list").innerHTML = agents.map((agent) => `
      <button type="button"
        onclick="selectEDRAgent('${agent.agent_id}')"
        style="width:100%; text-align:left; background:${edrActionsState.selectedAgentId === agent.agent_id ? '#10321a' : '#0f1729'}; border:1px solid ${edrActionsState.selectedAgentId === agent.agent_id ? '#00ff00' : '#1f3b23'}; color:#00ff00; padding:10px 12px; border-radius:6px; cursor:pointer; display:flex; justify-content:space-between; align-items:flex-start; gap:10px;">
        <span>
          <strong style="display:block; font-size:12px;">${escapeHTML(agent.hostname)}</strong>
          <small style="color:#8cb6ff;">${escapeHTML(agent.os_type)} • ${escapeHTML(agent.agent_id.substring(0, 8))}</small>
        </span>
        <span style="font-size:11px; color:#00ff00;">Online</span>
      </button>
    `).join("");

    const preferredAgent = agents.find((agent) => agent.os_type === edrActionsState.selectedOsType) || agents[0];
    if (preferredAgent) {
      await selectEDRAgent(preferredAgent.agent_id);
    }
  } catch (error) {
    console.error("Failed to load EDR actions modal:", error);
    document.getElementById("edr-actions-content").innerHTML = `<div style="padding:16px; border:1px solid #ff4444; border-radius:6px; color:#ff4444;">Failed to load agents: ${escapeHTML(error.message)}</div>`;
  }
}

async function selectEDRAgent(agentId) {
  edrActionsState.selectedAgentId = agentId;
  const selectedAgent = edrActionsState.agents.find((agent) => agent.agent_id === agentId);
  edrActionsState.selectedTelemetryIndex = null;
  edrActionsState.agentActions = [];

  document.getElementById("edr-actions-agent-list").innerHTML = edrActionsState.agents.map((agent) => `
    <button type="button"
      onclick="selectEDRAgent('${agent.agent_id}')"
      style="width:100%; text-align:left; background:${agent.agent_id === agentId ? '#10321a' : '#0f1729'}; border:1px solid ${agent.agent_id === agentId ? '#00ff00' : '#1f3b23'}; color:#00ff00; padding:10px 12px; border-radius:6px; cursor:pointer; display:flex; justify-content:space-between; align-items:flex-start; gap:10px;">
      <span>
        <strong style="display:block; font-size:12px;">${escapeHTML(agent.hostname)}</strong>
        <small style="color:#8cb6ff;">${escapeHTML(agent.os_type)} • ${escapeHTML(agent.agent_id.substring(0, 8))}</small>
      </span>
      <span style="font-size:11px; color:#00ff00;">Online</span>
    </button>
  `).join("");

  document.getElementById("edr-actions-telemetry-list").innerHTML = '<div style="padding:16px; color:#64748b;">Loading telemetry...</div>';
  document.getElementById("edr-actions-content").innerHTML = '<div style="padding:16px; color:#64748b;">Select a telemetry event to view details and response options.</div>';

  if (!selectedAgent) {
    return;
  }

  document.getElementById("edr-actions-subtitle").textContent = `${selectedAgent.hostname} • ${selectedAgent.os_type} • latest telemetry and response options`;

  try {
    const response = await authFetch(`/api/edr-agents/${agentId}/telemetry?limit=12`);
    if (!response.ok) throw new Error(`API Error: ${response.status}`);

    const telemetry = await response.json();
    edrActionsState.telemetry = telemetry;

    if (!telemetry.length) {
      document.getElementById("edr-actions-telemetry-list").innerHTML = `
        <div style="padding:16px; border:1px dashed #1f3b23; border-radius:6px; color:#64748b;">
          No events from this agent.
        </div>
      `;
      document.getElementById("edr-actions-content").innerHTML = '<div style="padding:16px; color:#64748b;">No events from this agent.</div>';
      return;
    }

    renderTelemetryList(selectedAgent);
    const firstVisibleIndex = getFilteredTelemetryEntries()[0]?.index;
    if (firstVisibleIndex !== undefined) {
      await selectEDRTelemetry(firstVisibleIndex);
    }
  } catch (error) {
    console.error("Failed to load telemetry for actions modal:", error);
    document.getElementById("edr-actions-telemetry-list").innerHTML = `<div style="padding:16px; border:1px solid #ff4444; border-radius:6px; color:#ff4444;">Failed to load telemetry: ${escapeHTML(error.message)}</div>`;
    document.getElementById("edr-actions-content").innerHTML = '<div style="padding:16px; color:#64748b;">Select a telemetry event to view details and response options.</div>';
  }
}

async function selectEDRTelemetry(eventIndex) {
  edrActionsState.selectedTelemetryIndex = eventIndex;
  const telemetryEvent = edrActionsState.telemetry[eventIndex];
  if (!telemetryEvent) {
    document.getElementById("edr-actions-content").innerHTML = '<div style="padding:16px; color:#64748b;">No events from this agent.</div>';
    return;
  }

  renderTelemetryList({ agent_id: edrActionsState.selectedAgentId }, eventIndex);

  try {
    const response = await authFetch(`/api/edr-agents/${edrActionsState.selectedAgentId}/actions`);
    if (response.ok) {
      edrActionsState.agentActions = await response.json();
    } else {
      edrActionsState.agentActions = [];
    }
  } catch (error) {
    console.error("Failed to load agent actions:", error);
    edrActionsState.agentActions = [];
  }

  document.getElementById("edr-actions-content").innerHTML = renderTelemetryDetailPanel(telemetryEvent, edrActionsState.selectedAgentId, eventIndex);
}

function getTelemetryCategory(event) {
  const payload = event.data || {};
  return event.event_category || event.category || payload.event_category || payload.category || "Telemetry";
}

function getFilteredTelemetryEntries() {
  return edrActionsState.telemetry
    .map((event, index) => ({ event, index }))
    .filter(({ event }) => edrActionsState.telemetryCategory === "All" || getTelemetryCategory(event) === edrActionsState.telemetryCategory);
}

function updateTelemetryCategoryControls() {
  document.querySelectorAll("#edr-actions-telemetry-categories [data-telemetry-category]").forEach((button) => {
    const active = button.dataset.telemetryCategory === edrActionsState.telemetryCategory;
    button.setAttribute("aria-selected", String(active));
    button.style.background = active ? "rgba(217,184,255,0.14)" : "#0D0D0D";
    button.style.borderColor = active ? "#D9B8FF" : "rgba(217,184,255,0.45)";
    button.style.color = active ? "#D9B8FF" : "#8cb6ff";
  });
}

function renderTelemetryList(agent, selectedIndex = edrActionsState.selectedTelemetryIndex) {
  const entries = getFilteredTelemetryEntries();
  const total = edrActionsState.telemetry.length;
  document.getElementById("edr-actions-telemetry-count").textContent = `${entries.length}/${total} event${total === 1 ? "" : "s"}`;
  updateTelemetryCategoryControls();

  if (!entries.length) {
    document.getElementById("edr-actions-telemetry-list").innerHTML = `<div style="padding:16px; border:1px dashed #1f3b23; border-radius:6px; color:#64748b;">No ${escapeHTML(edrActionsState.telemetryCategory.toLowerCase())} events from this agent.</div>`;
    return;
  }

  document.getElementById("edr-actions-telemetry-list").innerHTML = entries
    .map(({ event, index }) => renderTelemetryPickerCard(agent, event, index, index === selectedIndex))
    .join("");
}

async function setTelemetryCategory(category) {
  edrActionsState.telemetryCategory = category;
  const firstVisibleIndex = getFilteredTelemetryEntries()[0]?.index;
  renderTelemetryList({ agent_id: edrActionsState.selectedAgentId }, firstVisibleIndex);
  if (firstVisibleIndex !== undefined) {
    await selectEDRTelemetry(firstVisibleIndex);
  } else {
    edrActionsState.selectedTelemetryIndex = null;
    document.getElementById("edr-actions-content").innerHTML = '<div style="padding:16px; color:#64748b;">Select another telemetry category or wait for a matching event.</div>';
  }
}

function renderTelemetryPickerCard(agent, event, eventIndex, isSelected = false) {
  const payload = event.data || {};
  const title = [event.event_type, event.event_subtype].filter(Boolean).join(" / ") || "Telemetry Event";
  const detail = payload.process_name || payload.name || payload.file_path || payload.remote_ip || payload.destination_ip || payload.ip || "No key details";
  const time = event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : "-";
  const severity = event.severity || "info";
  const confidence = payload.confidence || payload.malware_confidence || payload.network_risk_score;
  const confidenceLabel = confidence !== undefined && confidence !== null ? `${Math.round(Number(confidence) * 100)}%` : "n/a";

  return `
    <button type="button"
      onclick="selectEDRTelemetry(${eventIndex})"
      style="width:100%; text-align:left; background:${isSelected ? 'rgba(217,184,255,0.14)' : '#0D0D0D'}; border:1px solid ${isSelected ? '#D9B8FF' : 'rgba(217,184,255,0.45)'}; color:#D9B8FF; padding:10px 12px; border-radius:6px; cursor:pointer; display:flex; flex-direction:column; gap:6px;">
      <div style="display:flex; justify-content:space-between; gap:10px; align-items:flex-start;">
        <strong style="font-size:12px; color:#8cb6ff;">${escapeHTML(title)}</strong>
        <span style="font-size:11px; color:#64748b;">${escapeHTML(time)}</span>
      </div>
      <div style="font-size:12px;">${escapeHTML(detail)}</div>
      <div style="display:flex; justify-content:space-between; gap:10px; font-size:11px; color:#8cb6ff;">
        <span>${escapeHTML(severity)}</span>
        <span>${escapeHTML(confidenceLabel)}</span>
      </div>
    </button>
  `;
}

function getTelemetryActionOptions(event) {
  const payload = event.data || {};
  const actions = [];

  if (payload.pid !== undefined && payload.pid !== null) {
    actions.push({
      label: "Kill Process",
      actionType: "kill_process",
      params: { pid: payload.pid },
      hint: `Terminate PID ${payload.pid}`,
    });
  }

  if (payload.file_path) {
    actions.push({
      label: "Quarantine File",
      actionType: "quarantine_file",
      params: { file_path: payload.file_path },
      hint: `Move ${payload.file_path} to quarantine`,
    });
  }

  return actions;
}

function renderTelemetryDetailPanel(event, agentId, eventIndex = 0) {
  const payload = event.data || {};
  const actions = getTelemetryActionOptions(event);
  const relatedActions = edrActionsState.agentActions.filter((action) => {
    const actionParams = action.action_params || {};
    if (payload.pid !== undefined && payload.pid !== null && String(actionParams.pid) === String(payload.pid)) {
      return true;
    }
    if (payload.file_path && actionParams.file_path && String(actionParams.file_path) === String(payload.file_path)) {
      return true;
    }
    return false;
  });
  const title = [event.event_type, event.event_subtype].filter(Boolean).join(" / ");
  const detail = payload.process_name || payload.name || payload.file_path || payload.remote_ip || payload.destination_ip || payload.ip || "No key details";
  const timestamp = event.timestamp ? new Date(event.timestamp).toLocaleString() : "-";
  const severity = event.severity || "info";
  const confidence = payload.confidence || payload.malware_confidence || payload.network_risk_score;
  const confidenceLabel = confidence !== undefined && confidence !== null ? `${Math.round(Number(confidence) * 100)}%` : "n/a";

  return `
    <div style="border:1px solid #1f3b23; border-radius:8px; padding:14px; background:#0b1117; display:flex; flex-direction:column; gap:12px; margin-bottom:12px;">
      <div style="display:flex; justify-content:space-between; gap:12px; align-items:flex-start;">
        <div>
          <div style="font-size:13px; color:#8cb6ff; margin-bottom:4px;">${escapeHTML(title || 'Telemetry Event')}</div>
          <div style="font-size:12px; color:#00ff00;">${escapeHTML(detail)}</div>
        </div>
        <div style="text-align:right; font-size:11px; color:#64748b; white-space:nowrap;">
          <div>${escapeHTML(severity)}</div>
          <div>${escapeHTML(confidenceLabel)}</div>
          <div>${escapeHTML(timestamp)}</div>
        </div>
      </div>
      <pre style="margin:0; padding:10px; border:1px solid #1f3b23; border-radius:6px; background:#081017; color:#8cb6ff; font-size:11px; white-space:pre-wrap; word-break:break-word;">${escapeHTML(JSON.stringify(payload, null, 2))}</pre>
      <div style="display:flex; flex-wrap:wrap; gap:8px; align-items:center;">
        ${actions.length ? actions.map((action, actionIndex) => `
          <button type="button" onclick="dispatchTelemetryAction('${agentId}', ${eventIndex}, ${actionIndex})"
            style="background:#00331a; border:1px solid #00ff00; color:#00ff00; padding:8px 10px; border-radius:4px; cursor:pointer; font-family:inherit; font-size:12px;">
            ${escapeHTML(action.label)}
          </button>
        `).join("") : '<span style="color:#64748b; font-size:12px;">No direct response actions available for this telemetry event.</span>'}
      </div>
      ${relatedActions.length ? `
        <div style="margin-top:2px; padding-top:12px; border-top:1px solid #1f3b23;">
          <div style="font-size:11px; color:#8cb6ff; margin-bottom:8px;">Recent Related Actions</div>
          ${relatedActions.slice(0, 5).map((action) => `
            <div style="padding:8px 10px; margin-bottom:6px; border:1px solid #1f3b23; border-radius:6px; background:#0f1729; display:flex; flex-direction:column; gap:4px;">
              <div style="display:flex; justify-content:space-between; gap:10px; font-size:11px;">
                <span>${escapeHTML(action.action_type)}</span>
                <span>${escapeHTML(action.status)}</span>
              </div>
              <div style="font-size:11px; color:#64748b;">${escapeHTML(action.result_message || action.result || 'No result yet')}</div>
            </div>
          `).join("")}
        </div>
      ` : ''}
    </div>
  `;
}

async function dispatchTelemetryAction(agentId, eventIndex, actionIndex) {
  const telemetryEvent = edrActionsState.telemetry[eventIndex];
  if (!telemetryEvent) {
    showEDRMessage("Selected telemetry event is no longer available.", "error");
    return;
  }

  const actions = getTelemetryActionOptions(telemetryEvent);
  const selectedAction = actions[actionIndex];
  if (!selectedAction) {
    showEDRMessage("Selected action is no longer available.", "error");
    return;
  }

  try {
    const response = await authFetch(`/api/edr-agents/${agentId}/actions`, {
      method: "POST",
      body: JSON.stringify({
        action_type: selectedAction.actionType,
        action_params: selectedAction.params,
      }),
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Failed to dispatch action");
    }

    const payload = telemetryEvent.data || {};
    showEDRMessage(`Dispatched ${selectedAction.actionType} for ${payload.process_name || payload.file_path || payload.remote_ip || "selected telemetry"}`, "success");
    await selectEDRAgent(agentId);
  } catch (error) {
    console.error("Failed to dispatch telemetry action:", error);
    showEDRMessage(`Action dispatch failed: ${error.message}`, "error");
  }
}

document.getElementById("edr-actions-modal").addEventListener("click", function(e) {
  if (e.target === this) closeEDRActionsModal();
});

document.addEventListener("keydown", function(e) {
  if (e.key === "Escape") {
    if (document.getElementById("edr-actions-modal").style.display === "flex") {
      closeEDRActionsModal();
    }
  }
});

function showEDRMessage(text, type = "success") {
  const container = document.getElementById("edr-message-container")
  const div = document.createElement("div");
  div.className = type;
  div.textContent = text;
  container.appendChild(div);
  setTimeout(() => div.remove(), 5000);
}

// Load EDR agents when page loads
refreshEDRAgents();

// Auto-refresh every 30 seconds
setInterval(refreshEDRAgents, 30000);

