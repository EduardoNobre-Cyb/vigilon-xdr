// Moved out of templates/login.html (was an inline <script>). Loaded as a classic
// script so its functions stay global for the onclick="..." handlers.
// Typewriter effect for the terminal prompt
const messages = [
  "Initialising secure connection...",
  "Awaiting analyst credentials.",
];
let msgIndex = 0;
let charIndex = 0;
const el = document.getElementById('terminal-text');

function typeWriter() {
  const msg = messages[msgIndex];
  if (charIndex < msg.length) {
    el.textContent += msg[charIndex];
    charIndex++;
    setTimeout(typeWriter, 45);
  } else {
    // Pause then clear and move to next message
    setTimeout(() => {
      el.textContent = '';
      charIndex = 0;
      msgIndex = (msgIndex + 1) % messages.length;
      typeWriter();
    }, 2500);
  }
}
typeWriter();

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

async function handleLogin(event) {
  event.preventDefault();

  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;
  const errorEl = document.getElementById('login-error');
  const btn = document.getElementById('login-btn');
  const btnText = document.getElementById('btn-text');

  // Reset error state
  errorEl.style.display = 'none';
  errorEl.textContent = '';
  btn.disabled = true;
  btnText.textContent = '[ AUTHENTICATING... ]';

  try {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    const data = await response.json();

    if (!response.ok) {
      // Show error returned from server
      errorEl.textContent = '⚠ ' + (data.error || 'Authentication failed.');
      errorEl.style.display = 'block';
      btn.disabled = false;
      btnText.textContent = '[ AUTHENTICATE ]';
      return;
    }

    // Store token and user info
    localStorage.setItem('auth_token', data.token);
    localStorage.setItem('user_role', data.role);
    localStorage.setItem('user_name', data.name);
    localStorage.setItem('must_change_password', data.must_change_password ? 'true' : 'false');

    // Tell the dashboard to play the splash animation once, on its next load
    sessionStorage.setItem('vigilon_splash', '1');

    btnText.textContent = '[ ACCESS GRANTED ]';

    // Brief pause so the user sees the success state, then redirect
    setTimeout(() => {
      if (data.must_change_password) {
        window.location.replace('/change-password');
      } else {
        window.location.replace('/');
      }
    }, 600);

  } catch (err) {
    errorEl.textContent = '⚠ Could not reach server. Is the Flask app running?';
    errorEl.style.display = 'block';
    btn.disabled = false;
    btnText.textContent = '[ AUTHENTICATE ]';
  }
}
