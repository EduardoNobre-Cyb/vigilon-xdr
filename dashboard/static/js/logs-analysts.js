// Moved out of templates/dashboard.html (was an inline <script>). Loaded as a classic
// script so its functions stay global for the onclick="..." handlers.
// Fetch and display logs
async function loadLogs() {
  const response = await authFetch("/api/logs");
  const data = await response.json();
  const container = document.getElementById("logs-container");
  if (data.logs.length === 0) {
    container.innerHTML = "<p>No logs ingested</p>";
    return;
  }
  let html = `<p>${data.count} logs ingested</p>`;
  for (const log of data.logs) {
    html += `<div class="log-card"><pre>${JSON.stringify(log, null, 2)}</pre></div>`;
  }
  container.innerHTML = html;
}
setInterval(loadLogs, 10000);
loadLogs();

function normalizeAnalystRole(role) {
  const normalized = (role || '').toString().trim().toLowerCase().replace(/\s+/g, '_');
  const allowedRoles = ['analyst', 'senior_analyst', 'manager', 'admin'];
  return allowedRoles.includes(normalized) ? normalized : 'analyst';
}

function displayAnalystRole(role) {
  return normalizeAnalystRole(role).replace(/_/g, ' ');
}

function normalizeNotificationThreshold(threshold) {
  const normalized = (threshold || '').toString().trim().toLowerCase();
  const allowedThresholds = ['low', 'medium', 'high', 'critical'];
  return allowedThresholds.includes(normalized) ? normalized : 'medium';
}

// Fetch and display analysts
async function loadAnalysts() {
  const container = document.getElementById("analysts-container");
  try {
    const response = await authFetch("/api/analysts");
    const data = await response.json();

    if (!data.analyst || data.analyst.length === 0) {
      container.innerHTML = "<p>No analysts registered</p>";
      return;
    }

    let html = `<p>${data.analyst.length} analysts registered</p>`;
    html += `<table>
      <thead>
        <tr>
          <th>Name</th>
          <th>Email</th>
          <th>Role</th>
          <th>Status</th>
          <th>Notification Threshold</th>
          <th class="analyst-edit-cell"></th>
        </tr>
      </thead>
      <tbody>`;

    for (const analyst of data.analyst) {
      const statusBadge = analyst.active ? '✅ Active' : '❌ Inactive';
      const escapedName = analyst.name.replace(/'/g, "\\'");
      const escapedEmail = analyst.email.replace(/'/g, "\\'");
      const normalizedRole = normalizeAnalystRole(analyst.role);
      const escapedRole = normalizedRole.replace(/'/g, "\\'");
      const normalizedThreshold = normalizeNotificationThreshold(analyst.notification_threshold);
      const escapedThreshold = normalizedThreshold.replace(/'/g, "\\'");
      html += `<tr>
        <td>${analyst.name}</td>
        <td>${analyst.email}</td>
        <td>${displayAnalystRole(analyst.role)}</td>
        <td>${statusBadge}</td>
        <td>${normalizedThreshold}</td>
        <td class="analyst-edit-cell">
          <button onclick="openEditModal(${analyst.id}, '${escapedName}', '${escapedEmail}', '${escapedRole}', '${escapedThreshold}', ${analyst.active})"
            class="analyst-edit-btn">
            ✏️ Edit
          </button>
        </td>
      </tr>`;
    }

    html += `</tbody></table>`;
    container.innerHTML = html;
  } catch (error) {
    console.error("Failed to load analysts:", error);
    container.innerHTML = "<p>Failed to load analysts data</p>";
  }
}

// Load analysts on page load and every 30 seconds
loadAnalysts();
setInterval(loadAnalysts, 30000);

let _editAnalystId = null;
let _editAnalystActive = null;
let _editAnalystName = '';
let _editAnalystEmail = '';
let _editAnalystRole = 'analyst';
let _editAnalystThreshold = 'medium';

function openEditModal(id, name, email, role, notificationThreshold, active) {
  _editAnalystId = id;
  _editAnalystActive = active;
  _editAnalystName = name;
  _editAnalystEmail = email;
  _editAnalystRole = normalizeAnalystRole(role);
  _editAnalystThreshold = normalizeNotificationThreshold(notificationThreshold);
  document.getElementById('modal-analyst-name').textContent = name;
  document.getElementById('modal-analyst-input-name').value = name;
  document.getElementById('modal-analyst-input-email').value = email;
  document.getElementById('modal-analyst-input-role').value = _editAnalystRole;
  document.getElementById('modal-analyst-input-threshold').value = _editAnalystThreshold;
  document.getElementById('modal-toggle-active-btn').textContent =
    active ? '🔴 Set as Inactive' : '🟢 Set as Active';
  const modal = document.getElementById('edit-analyst-modal');
  modal.style.display = 'flex';
}

function closeEditModal() {
  document.getElementById('edit-analyst-modal').style.display = 'none';
  _editAnalystId = null;
  _editAnalystActive = null;
  _editAnalystName = '';
  _editAnalystEmail = '';
  _editAnalystRole = 'analyst';
  _editAnalystThreshold = 'medium';
}

async function modalSaveDetails() {
  if (_editAnalystId === null) return;

  const name = document.getElementById('modal-analyst-input-name').value.trim();
  const email = document.getElementById('modal-analyst-input-email').value.trim();
  const role = normalizeAnalystRole(document.getElementById('modal-analyst-input-role').value);
  const notification_threshold = normalizeNotificationThreshold(document.getElementById('modal-analyst-input-threshold').value);

  if (!name) {
    alert('Name cannot be empty.');
    return;
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    alert('Please enter a valid email address.');
    return;
  }

  try {
    const res = await authFetch(`/api/analysts/${_editAnalystId}`, {
      method: 'PUT',
      body: JSON.stringify({ name, email, role, notification_threshold }),
    });
    const data = await res.json();

    if (data.success) {
      closeEditModal();
      loadAnalysts();
    } else {
      alert(data.message || 'Update failed.');
    }
  } catch (err) {
    alert('Could not reach server.');
  }
}

async function modalToggleActive() {
  if (_editAnalystId === null) return;
  const newActive = !_editAnalystActive;
  try {
    const res = await authFetch(`/api/analysts/${_editAnalystId}`, {
      method: 'PUT',
      body: JSON.stringify({ active: newActive }),
    });
    const data = await res.json();
    if (data.success) {
      closeEditModal();
      loadAnalysts();
    } else {
      alert(data.message || 'Update failed.');
    }
  } catch (err) {
    alert('Could not reach server.');
  }
}

async function modalResetPassword() {
  if (_editAnalystId === null) return;
  const name = document.getElementById('modal-analyst-name').textContent;
  if (!confirm(`Reset password for ${name}?\n\nThey will receive the default password and be forced to change it on next login.`)) return;
  try {
    const res = await authFetch(`/api/analysts/${_editAnalystId}/reset-password`, { method: 'POST' });
    const data = await res.json();
    alert(data.message || (data.success ? 'Password reset.' : 'Reset failed.'));
    closeEditModal();
  } catch (err) {
    alert('Could not reach server.');
  }
}

// --- Auth helpers ---

function logout() {
  localStorage.removeItem('auth_token');
  localStorage.removeItem('user_role');
  localStorage.removeItem('user_name');
  window.location.replace('/login');
}

// Show the logged-in user's name in the header
(function initGreeting() {
  const name = localStorage.getItem('user_name');
  const role = localStorage.getItem('user_role');
  if (role !== 'admin') {
    const item = document.getElementById('menu-analyst-team');
    if (item) {
      item.style.display = 'none';
    }
  }
  const el = document.getElementById('user-greeting');
  if (el && name) {
    el.textContent = `${name}${role === 'admin' ? ' (Admin)' : ''}`;
  }
})();
