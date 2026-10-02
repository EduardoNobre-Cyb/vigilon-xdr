// Moved out of templates/change_password.html (was an inline <script>). Loaded as a classic
// script so its functions stay global for the onclick="..." handlers.
function togglePassword(inputId, btn) {
  const input = document.getElementById(inputId);
  if (input.type === 'password') {
    input.type = 'text';
    btn.textContent = '🙈';
  } else {
    input.type = 'password';
    btn.textContent = '👁';
  }
}

// Show a different subtitle if forced by first login
(function() {
  if (localStorage.getItem('must_change_password') === 'true') {
    document.getElementById('page-subtitle').textContent =
      'First login detected \u2014 you must set a permanent password before continuing.';
  }
})();

async function handleChange(event) {
  event.preventDefault();

  const currentPw  = document.getElementById('current-password').value;
  const newPw      = document.getElementById('new-password').value;
  const confirmPw  = document.getElementById('confirm-password').value;
  const errorEl    = document.getElementById('change-error');
  const btn        = document.getElementById('change-btn');
  const btnText    = document.getElementById('btn-text');

  // Reset error state
  errorEl.style.display = 'none';
  errorEl.textContent = '';

  // Client-side validation
  if (!currentPw || !newPw || !confirmPw) {
    errorEl.textContent = '\u26a0 All fields are required.';
    errorEl.style.display = 'block';
    return;
  }
  if (newPw.length < 8) {
    errorEl.textContent = '\u26a0 New password must be at least 8 characters.';
    errorEl.style.display = 'block';
    return;
  }
  if (newPw !== confirmPw) {
    errorEl.textContent = '\u26a0 New passwords do not match.';
    errorEl.style.display = 'block';
    return;
  }
  if (newPw === 'ChangeMe123!') {
    errorEl.textContent = '\u26a0 You must choose a unique password.';
    errorEl.style.display = 'block';
    return;
  }

  btn.disabled = true;
  btnText.textContent = '[ UPDATING... ]';

  try {
    const token = localStorage.getItem('auth_token');
    const response = await fetch('/api/auth/change-password', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token,
      },
      body: JSON.stringify({
        current_password: currentPw,
        new_password: newPw,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      errorEl.textContent = '\u26a0 ' + (data.error || 'Password change failed.');
      errorEl.style.display = 'block';
      btn.disabled = false;
      btnText.textContent = '[ UPDATE PASSWORD ]';
      return;
    }

    // Replace stored token with the fresh one (must_change_password is now false)
    localStorage.setItem('auth_token', data.token);
    localStorage.setItem('must_change_password', 'false');

    btnText.textContent = '[ PASSWORD UPDATED ]';

    // Brief pause, then go to dashboard
    setTimeout(() => {
      window.location.replace('/');
    }, 800);

  } catch (err) {
    errorEl.textContent = '\u26a0 Could not reach server. Is the Flask app running?';
    errorEl.style.display = 'block';
    btn.disabled = false;
    btnText.textContent = '[ UPDATE PASSWORD ]';
  }
}
