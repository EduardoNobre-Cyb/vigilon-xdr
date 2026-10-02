// Moved out of templates/dashboard.html (was an inline <script>). Loaded as a classic
// script so its functions stay global for the onclick="..." handlers.
  let currentReviewThreatId = null; // Track which threat is being reviewed


  async function loadNeedsReviewQueue() {
    const container = document.getElementById("needs-review-container");
    try {
      const res = await authFetch("/api/reviews/pending");
      const data = await res.json();

      if (!data.items || data.items.length === 0) {
        container.innerHTML = "<div class='no-data'>No pending reviews 🎉</div>";
        return;
      }

      container.innerHTML = data.items
        .map((item) => {
          // Calculate SLA status
          let slaClass = "sla-ok";
          let slaLabel = "On Track";
          if (item.sla_breached) {
            slaClass = "sla-breached";
            slaLabel = "❌ BREACHED";
          } else if (item.sla_deadline) {
            const now = new Date();
            const deadline = new Date(item.sla_deadline);
            const percentRemaining =
              ((deadline - now) / (deadline - new Date(item.created_at))) * 100;
            if (percentRemaining < 20) {
              slaClass = "sla-critical";
              slaLabel = "🔴 Critical";
            } else if (percentRemaining < 50) {
              slaClass = "sla-warning";
              slaLabel = "🟡 Warning";
            }
          }

          // Lock status
          let lockStatus = "";
          if (item.locked_by && item.locked_by !== currentUserId) {
            lockStatus = `<span style="color:#ff6b6b;">🔒 Locked by ${item.locked_analyst_name}</span>`;
          }

          return  `
          <div class="threat-item" style="display:flex; justify-content:space-between;align-items:center;gap:12px;">
            <div>
              <strong>${item.threat_type}</strong> - <span class="severity-${(item.severity || "low").toLowerCase()}">${item.severity}</span><br>
              <small>Risk: ${item.risk_score}/10 | ${item.asset_name} → ${item.vulnerability_name}</small>
            </div>
            <button class="btn" onclick="openReviewModal(${item.id})">Review</button>
          </div>
        `;
      })
          .join("");
    } catch (e) {
      container.innerHTML =
      "<div class='no-data'>Failed to load review queue</div>";
    }

 }

 // Add CSS for SLA visual states
 const style = document.createElement("style");
 style.textContent = `
.threat-item.sla-ok { border-left-color: #D9B8FF; background: rgba(217,184,255,0.10); }
 .threat-item.sla-warning { border-left-color: #ffaa00; background: rgba(255,170,0,0.1); }
 .threat-item.sla-critical { border-left-color: #ff6b6b; background: rgba(255,107,107,0.1); }
 .threat-item.sla-breached { border-left-color: #ff0000; background: rgba(255,0,0,0.15); }
 `;
 document.head.appendChild(style);

function closeReviewModal() {
  // Unlock if not saved
  if (currentReviewThreatId) {
    authFetch(`/api/reviews/${currentReviewThreatId}/unlock`, { method: "POST",
    });
  }

  document.getElementById("review-modal").style.display = "none";
  currentReviewThreatId = null;
}

function toggleCustomThreatInput() {
  const finalTypeSelect = document.getElementById("review-final-type");
  const customInputContainer = document.getElementById("custom-threat-input-container");

  if (finalTypeSelect && customInputContainer) {
    if (finalTypeSelect.value === "Other") {
      customInputContainer.style.display = "block";
    } else {
      customInputContainer.style.display = "none";
    }
  }
}

async function openReviewModal(threatId) {
  currentReviewThreatId = threatId;

  // Try to claim - determine whether its need-review OR recent threat
  let claimRes = await authFetch(`/api/reviews/${threatId}/claim`, { method: "POST" });
  let claimData = await claimRes.json();

  if (claimData.success) {
    // Successfully claimed for review
    // Lock it and loads need-review modal content
    let lockRes = await authFetch(`/api/reviews/${threatId}/lock`, { method: "POST" });
    let lockData = await lockRes.json();
    if (!lockData.success) {
      alert(lockData.message);
      return;
    }
    await loadNeedsReviewModal(threatId);
    updateModalButtons(false); // False = needs review workflow
  } else {
    // Failed to claim for review - its Recent threat
    // Load recent-threat modal content
    await loadRecentThreatReviewModal(threatId);
    updateModalButtons(true); // True = recent threat workflow
  }
}

async function loadNeedsReviewModal(threatId) {
  const modal = document.getElementById("review-modal");
  const body = document.getElementById("review-modal-body");
  body.innerHTML = "Loading...";
  modal.style.display = "flex";

  const res = await authFetch(`/api/reviews/${threatId}`);
  const data = await res.json();

  // Calculate confidence level and percentage
  const confidenceScore = data.ensemble_confidence || data.confidence_score || 0;
  const confidencePercent = Math.round(confidenceScore * 100);
  let confLevel = "low";
  if (confidencePercent >= 70) confLevel = "high";
  else if (confidencePercent >= 45) confLevel = "medium";
  const originLabel = data.origin === "edr_telemetry" ? "EDR Telemetry" : "Legacy Logs";
  const contextLabel = data.asset_name && data.vulnerability_name
    ? `${data.asset_name} (${data.asset_type}) → ${data.vulnerability_name}`
    : originLabel;

  body.innerHTML = `
    <p><strong>${data.threat_type}</strong> - <span class="severity-${data.severity.toLowerCase()}">${data.severity}</span></p>
    <p>Risk: ${data.risk_score}/10 | <span class="threat-confidence-${confLevel}">Confidence: ${confidencePercent}%</span> | MITRE: ${data.mitre_tactic || "N/A"}</p>
    <p>${contextLabel}</p>
    <p><small style="color:#888;">Source: ${originLabel}</small></p>
    <p>${data.vulnerability_description || ""}</p>

    <label style="color:#00ff00; font-size:14px; display:block; margin-bottom:8px; margin-top:12px;">Final Classification</label>
    <select id="review-final-type" onchange="toggleCustomThreatInput()" style="width:100%; margin-bottom:10px; background:#0f1729; border:1px solid #00ff00; color:#00ff00; padding:8px 10px; border-radius:3px; font-family:'Share Tech Mono','Courier New',monospace; font-size:13px;">
      <option value="">-- Select Classification --</option>
      <option value="Injection Attack">Injection Attack</option>
      <option value="Privilege Escalation">Privilege Escalation</option>
      <option value="Data Exfiltration">Data Exfiltration</option>
      <option value="Cross-Site Scripting">Cross-Site Scripting</option>
      <option value="Denial of Service">Denial of Service</option>
      <option value="Network Attack">Network Attack</option>
      <option value="Vulnerability Exploit">Vulnerability Exploit</option>
      <option value="Other">Other</option>
    </select>

    <div id="custom-threat-input-container" style="display:none; margin-bottom:10px;">
      <label style="color:#00ff00; font-size:14px; display:block; margin-bottom:8px; margin-top:12px;">Custom Threat Type</label>
      <input type="text" id="custom-threat-input" placeholder="Enter custom threat type..." style="width:100%; background:#0f1729; border:1px solid #00ff00; color:#00ff00; padding:8px 10px; border-radius:3px; font-family:'Share Tech Mono','Courier New',monospace; font-size:13px; box-sizing:border-box;">
    </div>

    <label style="color:#00ff00; font-size:14px; display:block; margin-bottom:8px; margin-top:12px;">Analyst Notes</label>
    <textarea id="review-notes" rows="5" style="width:100%; background:#0f1729; border:1px solid #00ff00; color:#00ff00; padding:8px 10px; border-radius:3px; font-family:'Share Tech Mono','Courier New',monospace; font-size:13px; box-sizing:border-box;" placeholder="Add any relevant notes or context here..."></textarea>
  `;
}

async function loadRecentThreatReviewModal(threatId) {
  const modal = document.getElementById("review-modal");
  const body = document.getElementById("review-modal-body");
  body.innerHTML = "Loading...";
  modal.style.display = "flex";

  const res = await authFetch(`/api/reviews/${threatId}`);
  const data = await res.json();

  const confidenceScore = data.ensemble_confidence || data.confidence_score || 0;
  const confidencePercent = Math.round(confidenceScore * 100);
  let confLevel = "low";
  if (confidencePercent >= 70) confLevel = "high";
  else if (confidencePercent >= 45) confLevel = "medium";
  const originLabel = data.origin === "edr_telemetry" ? "EDR Telemetry" : "Legacy Logs";
  const contextLabel = data.asset_name && data.vulnerability_name
    ? `${data.asset_name} (${data.asset_type}) → ${data.vulnerability_name}`
    : originLabel;

  body.innerHTML = `
    <p><strong>${data.threat_type}</strong> - <span class="severity-${data.severity.toLowerCase()}">${data.severity}</span></p>
    <p>Risk: ${data.risk_score}/10 | <span class="threat-confidence-${confLevel}">Confidence: ${confidencePercent}%</span> | MITRE: ${data.mitre_tactic || "N/A"}</p>
    <p>${contextLabel}</p>
    <p><small style="color:#888;">Source: ${originLabel}</small></p>
    <p>${data.vulnerability_description || ""}</p>

    <label style="color:#00ff00; font-size:14px; display:block; margin-bottom:8px; margin-top:12px;">Confirm or Change Classification</label>
    <select id="review-final-type" onchange="toggleCustomThreatInput()" style="width:100%; margin-bottom:10px; background:#0f1729; border:1px solid #00ff00; color:#00ff00; padding:8px 10px; border-radius:3px; font-family:'Share Tech Mono','Courier New',monospace; font-size:13px;">
      <option value="${data.threat_type}" selected>✓ Keep: ${data.threat_type}</option>
      <option value="">-- Change to --</option>
      <option value="Remote Code Execution">Remote Code Execution</option>
      <option value="Authentication Bypass">Authentication Bypass</option>
      <option value="SQL Injection">SQL Injection</option>
      <option value="Cross-Site Scripting">Cross-Site Scripting</option>
      <option value="Path Traversal">Path Traversal</option>
      <option value="Denial of Service">Denial of Service</option>
      <option value="Privilege Escalation">Privilege Escalation</option>
      <option value="Other">Other</option>
    </select>

    <div id="custom-threat-input-container" style="display:none; margin-bottom:10px;">
      <label style="color:#00ff00; font-size:14px; display:block; margin-bottom:8px; margin-top:12px;">Custom Threat Type</label>
      <input type="text" id="custom-threat-input" placeholder="Enter custom threat type..." style="width:100%; background:#0f1729; border:1px solid #00ff00; color:#00ff00; padding:8px 10px; border-radius:3px; font-family:'Share Tech Mono','Courier New',monospace; font-size:13px; box-sizing:border-box;">
    </div>

    <label style="color:#00ff00; font-size:14px; display:block; margin-bottom:8px; margin-top:12px;">Notes (Optional)</label>
    <textarea id="review-notes" rows="3" style="width:100%; background:#0f1729; border:1px solid #00ff00; color:#00ff00; padding:8px 10px; border-radius:3px; font-family:'Share Tech Mono','Courier New',monospace; font-size:13px; box-sizing:border-box;" placeholder="Why did you change it? (if changed)"></textarea>
  `;
}

function updateModalButtons(isRecentThreat) {
  const footer = document.querySelector("#review-modal > div > div:last-child");

  if (isRecentThreat) {
    footer.innerHTML = `
      <button class="btn" onclick="submitRecentThreatReview('confirm')">✓ Confirm</button>
      <button class="btn-review" onclick="submitRecentThreatReview('change')" style="margin-left:auto;">✎ Change</button>
    `;
  } else {
    footer.innerHTML = `
      <button class="btn" onclick="submitReviewDecision('confirm')">✓ Confirm</button>
      <button class="btn-falsepositive" onclick="submitReviewDecision('false_positive')" style="margin-left:auto;">False Positive</button>
      <button class="btn-escalate" onclick="submitReviewDecision('escalate')">Escalate</button>
    `;
  }
}

async function submitRecentThreatReview(action) {
  if (!currentReviewThreatId) return;

  const finalTypeSelect = document.getElementById("review-final-type");
  let finalType = finalTypeSelect.value;
  const notes = document.getElementById("review-notes").value.trim();

  // If "Other" is selected, use the custom input value
  if (finalType === "Other") {
    finalType = (document.getElementById("custom-threat-input")?.value || "").trim();
    if (!finalType) {
      alert("Please enter a custom threat type.");
      return;
    }
  }

  // For change action, don't allow "-- Change to --" placeholder
  if (action === "change" && finalType === "") {
    alert("Please select a classification to change to.");
    return;
  }

  const res = await authFetch(`/api/threats/${currentReviewThreatId}/review`, {
    method: "PUT",
    body: JSON.stringify({
      threat_type: finalType,
      analyst_notes: notes || `Analyst ${action} classification`,
      reviewed_by_analyst: true,
      action: action  // Pass action so backend can train models appropriately
    }),
  });

  const result = await res.json();
  if (result.success) {
    closeReviewModal();
    await loadRecentThreats(); // Refresh the recent threats list to reflect any changes
  } else {
    alert(result.message || "Failed to submit review.");
  }
}

async function submitReviewDecision(decision) {
  if (!currentReviewThreatId) return;

  const notes = (document.getElementById("review-notes")?.value || "").trim();
  let finalThreatType = document.getElementById("review-final-type")?.value || "";

  // If "Other" is selected, use the custom input value
  if (finalThreatType === "Other") {
    finalThreatType = (document.getElementById("custom-threat-input")?.value || "").trim();
    if (!finalThreatType) {
      alert("Please enter a custom threat type.");
      return;
    }
  }

  if (notes.length < 10) {
    alert("Please provide review notes (minimum 10 characters).");
    return;
  }

  if ((decision === "confirm" || decision === "escalate") && !finalThreatType) {
    alert("Please select a final classification.");
    return;
  }

  const res = await authFetch(
    `/api/reviews/${currentReviewThreatId}/decision`,
    {
      method: "POST",
      body: JSON.stringify({
        decision,
        final_threat_type: finalThreatType,
        notes,
      }),
    },
  );
  const data = await res.json();

  if (!data.success) {
    alert(data.message || "Failed to submit review.");
    return;
  }

  closeReviewModal();
  await loadNeedsReviewQueue();
  await loadRecentThreats(); // Refreshes card labels immediately
}

async function openAnalyticsModal() {
  document.getElementById("analytics-modal").style.display = "flex";
  await loadAnalyticsData();
}

function closeAnalyticsModal() {
  document.getElementById("analytics-modal").style.display = "none";
}

async function loadAnalyticsData() {
  const tbody = document.getElementById("analytics-body");
  try {
    const res = await authFetch("/api/analytics/reviewers");
    const data = await res.json();

    if (!data.items || data.items.length === 0) {
      tbody.innerHTML =
        `<tr><td colspan='7' style='text-align:center; padding:20px;'>No data yet. Reviews will appear
        here as analysts submit decisions.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.items
    .map(
      (a) => `
      <tr style="border-bottom:1px solid #333;">
        <td style="padding:8px;">${a.analyst_name}</td>
        <td style="padding:8px; text-align:center;">${a.total_reviews}</td>
        <td style="padding:8px; text-align:center; color:#00ff00;">${a.confirmed}</td>
        <td style="padding:8px; text-align:center; color:#ffaa00;">${a.false_positives}</td>
        <td style="padding:8px; text-align:center; color:#ff6b6b;">${a.escalated}</td>
        <td style="padding:8px; text-align:center;">${a.avg_review_minutes} min</td>
        <td style="padding:8px; text-align:center; color:${a.sla_compliance_pct >= 90 ?
        "#00ff00" : a.sla_compliance_pct >= 70 ? "#ffaa00" : "#ff6b6b"};">${a.sla_compliance_pct}%</td>
      </tr>
      `,
    )
    .join("");
  } catch (e) {
    console.error(e);
    tbody.innerHTML =
      `<tr><td colspan='7' style='text-align:center; padding:20px; color:#ff6b6b'>Failed to load analytics data.</td></tr>`;
  }
}

async function loadAttackPaths() {
  try {
    const response = await authFetch("/api/attack-paths");
    const data = await response.json();

    const container = document.getElementById("attack-paths-container");

    if (!data.success || data.count === 0) {
      container.innerHTML =`
        <p class="text-muted">No attack paths found.</p>`;
      return;
    }

    let html = `<table class="paths-table">
      <tr>
        <th>#</th>
        <th>Attack Path(Source → Target)</th>
        <th>Risk Score</th>
        <th>Difficulty</th>
        <th>Time (min)</th>
        <th>Success %</th>
        <th>Threat Actor</th>
      </tr>`;

    data.paths.forEach((path, idx) => {
      // Color code risk score
      let riskClass = "risk-low";
      if (path.risk_score >= 7) riskClass = "risk-high";
      else if (path.risk_score >= 4) riskClass = "risk-medium";

      // Difficulty bar visualization (0-10 scale)
      const diffPercent = (path.difficulty_score / 10) * 100;

      html += `<tr>
                <td><strong>${idx + 1}</strong></td>
                <td><strong>${path.source}</strong> → <strong>${path.target}</strong></td>
                <td class="${riskClass}">${path.risk_score.toFixed(2)}</td>
                <td>
                  <div class="difficulty-bar">
                    <div class="difficulty-fill" style="width:${diffPercent}%;"></div>
                  </div>
                  ${path.difficulty_score.toFixed(1)}/10
                </td>
                <td>${path.time_to_exploit}</td>
                <td>${path.success_probability.toFixed(0)}%</td>
                <td>${path.actor_profile}</td>
              </tr>`;
    });

    html += `</table>`;
    html += `<p class="text-muted mt-2">
            <small>
              Showing top ${Math.min(10, data.count)} of ${data.count} paths.
              <strong>Higher risk</strong> = easier to exploit + higher impact.
              Focus defenses on high-risk paths first.
            </small>
          </p>`;

    container.innerHTML = html;
  } catch (error) {
    console.error("Error loading attack paths:", error);
    document.getElementById("attack-paths-container").innerHTML =
      `<p class="text-muted">❌ Error loading attack paths: ${error.message}</p>`;
  }
}

// Load attack paths on initial dashboard load
document.addEventListener("DOMContentLoaded", function () {
  loadAttackPaths();
});

// Close modal on ESC key
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeAnalyticsModal();
});

// Toggle review queue collapse
function toggleReviewQueue() {
  const section = document.getElementById('needs-review-section');
  section.classList.toggle('collapsed');
  localStorage.setItem('review-queue-collapsed', section.classList.contains('collapsed'));
}

// Restore collapse state on load
window.addEventListener('DOMContentLoaded', () => {
  if (localStorage.getItem('review-queue-collapsed') === 'true') {
    document.getElementById('needs-review-section').classList.add('collapsed');
  }
});

// Initialize on page load
loadNeedsReviewQueue();
setInterval(loadNeedsReviewQueue, 30000); // Refresh review queue every 30s
setInterval(loadAttackPaths, 30000); // Refresh attack paths every 30s
