// Moved out of templates/dashboard.html (was an inline <script>). Loaded as a classic
// script so its functions stay global for the onclick="..." handlers.
// Fetch import/log statistics for dashboard
function loadDashboardStats() {
  authFetch("/api/logs")
    .then((r) => r.json())
    .then((data) => {
      document.getElementById("total-logs").textContent = data.logs.length;
      if (data.logs.length > 0) {
        const lastLog = data.logs[0];
        document.getElementById("last-import").textContent = 
          new Date(lastLog.timestamp).toLocaleString();
      }
    })
    .catch(() => {
      document.getElementById("total-logs").textContent = "0";
      document.getElementById("last-import").textContent = "Never";
    });

  authFetch("/api/assets")
    .then((r) => r.json())
    .then((data) => {
      document.getElementById("assets-count").textContent = data.assets.length;
    })
    .catch(() => {
      document.getElementById("assets-count").textContent = "0";
    });

  authFetch("/api/vulnerabilities")
    .then((r) => r.json())
    .then((data) => {
      document.getElementById("vulns-count").textContent = data.vulnerabilities.length;
    })
    .catch(() => {
      document.getElementById("vulns-count").textContent = "0";
    });
}

// Determine color/styling based on confidence
function confidenceLevel(score) {
  if (score >= 0.7) return "high";
  if (score >= 0.45) return "medium";
  return "low";
}

let currentPage = 1;
const pageSize = 20;

// Fetch recent threats for main dashboard
function loadRecentThreats(page = 1) {
  currentPage = page;
  const url = `/api/threats/recent?page=${currentPage}&page_size=${pageSize}`;

  authFetch(url)
    .then((r) => r.json())
    .then((data) => {
      const list = document.getElementById("threat-list");
      if (data.threats && data.threats.length > 0) {
        list.innerHTML = '';
        data.threats.forEach((threat) => {
          const confLevel = confidenceLevel(threat.confidence_score || 0);
          const confPercent = Math.round((threat.confidence_score || 0) * 100);
          const originLabel = threat.origin === "edr_telemetry" ? "EDR Telemetry" : "Legacy Logs";
          const contextLabel = threat.asset_name && threat.vulnerability_name
            ? `${threat.asset_name} → ${threat.vulnerability_name}`
            : originLabel;

          // Build analyst badge if reviewed
          let analystBadgeHTML = '';
          if (threat.reviewed_by_analyst && threat.reviewed_by_name) {
            analystBadgeHTML = `
              <span class="analyst-badge">
                <span class="analyst-badge-icon">👤</span>
                <span class="analyst-name">${threat.reviewed_by_name}</span>
              </span>
            `;
          }

          // Build review button for medium confidence
          let reviewButtonHTML = '';
          if (threat.confidence_score > 0.45 && threat.confidence_score < 0.70 && !threat.reviewed_by_analyst) {
            reviewButtonHTML = `
              <button class="btn-review" onclick="openReviewModal(${threat.id})">Review</button>
            `;
          }

          list.innerHTML += `
            <div class="threat-item">
              <div class="threat-header">
                <span class="threat-type">${threat.threat_type}</span>
              </div>

              <div class="threat-details">
                <span class="threat-severity severity-${threat.severity.toLowerCase()}">${threat.severity}</span>
                <span class="threat-risk">Risk: ${threat.risk_score}/10</span>

                <span class="threat-confidence threat-confidence-${confLevel}">
                  ${confPercent}%
                </span>

                ${analystBadgeHTML}

                ${reviewButtonHTML}
              </div>

              <div class="threat-info">
                ${contextLabel}
                <span class="threat-origin-badge">${originLabel}</span>
              </div>
            </div>
          `;
        });
      } else {
        list.innerHTML = '<div class="no-data">No recent threat activity</div>';
      }

      // Handle pagination metadata from response
      if (data.pagination) {
        updatePaginationControls(data.pagination);
      }
    })
    .catch(() => {
      document.getElementById("threat-list").innerHTML =
        '<div class="no-data">No recent threat activity</div>';
    });
}

// Update pagination controls based on API response
function updatePaginationControls(pagination) {
  const pageInfo = document.getElementById("threats-page-info");
  const prevBtn = document.getElementById("btn-threats-prev");
  const nextBtn = document.getElementById("btn-threats-next");

  if (pageInfo) {
    pageInfo.textContent = `${pagination.page}/${pagination.total_pages} (${pagination.total_count} total)`;
  }

  if (prevBtn) {
    prevBtn.disabled = false;
    prevBtn.onclick = () => {
      if (pagination.has_prev) {
        loadRecentThreats(pagination.page - 1);
      }
    };
  }

  if (nextBtn) {
    nextBtn.disabled = false;
    nextBtn.onclick = () => {
      if (pagination.has_next) {
        loadRecentThreats(pagination.page + 1);
      }
    };
  }
}

// Load threats on page init
document.addEventListener('DOMContentLoaded', () => {
  loadRecentThreats(1);  // Start at page 1
});

// Fetch detected anomalies
function loadAnomalies() {
  authFetch("/api/anomalies")
    .then((r) => r.json())
    .then((data) => {
      const list = document.getElementById("anomalies-list");
      if (data.anomalies && data.anomalies.length > 0) {
        list.innerHTML = '';
        data.anomalies.forEach((anomaly) => {
          list.innerHTML += `
            <div class="anomaly-item">
              <strong>🚨 ${anomaly.threat_type}</strong><br>
              <small>Score: ${anomaly.anomaly_score.toFixed(2)} | ${anomaly.reasons.join(', ')}</small>
            </div>
          `;
        });
      } else {
        list.innerHTML = '<div class="no-data">No anomalies detected</div>';
      }
    })
    .catch(() => {
      document.getElementById("anomalies-list").innerHTML =
        '<div class="no-data">No anomalies detected</div>';
    });
}

// Fetch attack patterns
function loadPatterns() {
  authFetch("/api/patterns")
    .then((r) => r.json())
    .then((data) => {
      const list = document.getElementById("patterns-list");
      if (data.patterns && data.patterns.length > 0) {
        list.innerHTML = '';
        data.patterns.forEach((pattern) => {
          list.innerHTML += `
            <div class="pattern-item">
              <strong>🎯 ${pattern.pattern}</strong><br>
              <small>Confidence: ${pattern.confidence.toFixed(2)} | ${pattern.description}</small>
            </div>
          `;
        });
      } else {
        list.innerHTML = '<div class="no-data">No attack patterns detected</div>';
      }
    })
    .catch(() => {
      document.getElementById("patterns-list").innerHTML =
        '<div class="no-data">No attack patterns detected</div>';
    });
}

// Load all dashboard data
function loadDashboard() {
  loadDashboardStats();
  loadRecentThreats();
  loadAnomalies();
  loadPatterns();
}

// Initialize dashboard
loadDashboard();

// Refresh data every 30 seconds
setInterval(loadDashboard, 30000);

// Fetch assets
authFetch("/api/assets")
  .then((r) => r.json())
  .then((data) => {
    const tbody = document.getElementById("assets-body");
    data.assets.forEach((asset) => {
      const riskClass = `criticality-${asset.risk_level.toLowerCase()}`;
      tbody.innerHTML += `
                  <tr>
                      <td>${asset.id}</td>
                      <td>${asset.name}</td>
                      <td>${asset.type}</td>
                      <td class="${riskClass}">${asset.risk_level}</td>
                  </tr>
              `;
    });
  });

// Fetch vulnerabilities
authFetch("/api/vulnerabilities")
  .then((r) => r.json())
  .then((data) => {
    const tbody = document.getElementById("vulnerabilities-body");
    data.vulnerabilities.forEach((vuln) => {
      const severityClass = `severity-${vuln.severity.toLowerCase()}`;
      tbody.innerHTML += `
                  <tr>
                      <td>${vuln.id}</td>
                      <td>${vuln.name}</td>
                      <td class="${severityClass}">${vuln.severity}</td>
                      <td>${vuln.description || "N/A"}</td>
                  </tr>
              `;
    });
  });

// Fetch asset-vulnerability mappings
authFetch("/api/asset-vulnerabilities")
  .then((r) => r.json())
  .then((data) => {
    const tbody = document.getElementById("asset-vulns-body");
    data.asset_vulnerabilities.forEach((link) => {
      const severityClass = `severity-${link.severity.toLowerCase()}`;
      const riskClass = `criticality-${link.risk_level.toLowerCase()}`;
      tbody.innerHTML += `
                  <tr>
                      <td>${link.asset_name}</td>
                      <td>${link.asset_type}</td>
                      <td class="${riskClass}">${link.risk_level}</td>
                      <td>${link.vulnerability_name}</td>
                      <td class="${severityClass}">${link.severity}</td>
                      <td>${link.description || "N/A"}</td>
                  </tr>
              `;
    });
  });

// Hamburger menu toggle
function toggleMenu() {
  const menu = document.getElementById('dropdownMenu');
  menu.classList.toggle('show');
}

// Show specific page/section
function showPage(pageId) {
  // Hide all pages
  document.querySelectorAll('.page-section').forEach(page => {
    page.classList.remove('active');
  });

  // Show selected page
  const selectedPage = document.getElementById(pageId);
  if (selectedPage) {
    selectedPage.classList.add('active');
  }

  // Close dropdown
  document.getElementById('dropdownMenu').classList.remove('show');
}

// Close dropdown when clicking outside
window.addEventListener('click', function(e) {
  if (!e.target.matches('.hamburger-btn')) {
    const dropdown = document.getElementById('dropdownMenu');
    if (dropdown && dropdown.classList.contains('show')) {
      dropdown.classList.remove('show');
    }
  }
});
