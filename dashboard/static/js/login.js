const typingPhrases = [
  "Initializing secure connection...",
  "Awaiting analyst credentials...",
  "6 sensors connected.",
  "All agents operaitonal.",
  "ML models loaded: process, network, file.",
];
let phraseIdx = 0;
let charIdx = 0;
const termEl = document.getElementById("terminal-text");

function typeWriter() {
  const phrase = typingPhrases[phraseIdx];
  if (charIdx < phrase.length) {
    termEl.textContent += phrase[charIdx];
    charIdx++;
    setTimeout(typeWriter, 40 + Math.random() * 25);
  } else {
    setTimeout(() => {
      eraseText();
    }, 2200);
  }
}

function eraseText() {
  if (termEl.textContent.length > 0) {
    termEl.textContent = termEl.textContent.slice(0, -1);
    setTimeout(eraseText, 18);
  } else {
    charIdx = 0;
    phraseIdx = (phraseIdx + 1) % typingPhrases.length;
    setTimeout(typeWriter, 350);
  }
}

typeWriter();

function showLoginScreen(n) {
  document.querySelectorAll(".login-screen").forEach(function (s) {
    s.classList.remove("active");
  });
  var screen = document.getElementById("login-screen-" + n);
  if (screen) screen.classList.add("active");
}

function togglePassword(inputId, btn) {
  const input = document.getElementById(inputId);
  const icon = btn.querySelector("[data-icon]");
  if (input.type === "password") {
    input.type = "text";
    if (icon) {
      icon.dataset.icon = "eyeOff";
      icon.innerHTML = window.ICONS.eyeOff;
    }
  } else {
    input.type = "password";
    if (icon) {
      icon.dataset.icon = "eye";
      icon.innerHTML = window.ICONS.eye;
    }
  }
}

async function handleLogin(event) {
  event.preventDefault();

  const email = document.getElementById("email").value.trim();
  const password = document.getElementById("password").value;
  const errorEl = document.getElementById("login-error");
  const btn = document.getElementById("login-btn");
  const btnText = document.getElementById("btn-text");

  errorEl.style.display = "none";
  errorEl.textContent = "";
  btn.disabled = true;
  btnText.textContent = "Signing in...";

  try {
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    const data = await response.json();

    if (!response.ok) {
      errorEl.textContent = data.error || "Authentication failed.";
      errorEl.style.display = "block";
      btn.disabled = false;
      btnText.textContent = "Sign In";
      return;
    }

    localStorage.setItem("auth_token", data.token);
    localStorage.setItem("user_role", data.role);
    localStorage.setItem("user_name", data.name);
    localStorage.setItem("must_change_password", data.must_change_password ? "true" : "false");

    sessionStorage.setItem("vigilon_splash", "1");
    btnText.textContent = "Access Granted";

    setTimeout(() => {
      if (data.must_change_password) {
        window.location.replace("/change-password");
      } else {
        window.location.replace("/");
      }
    }, 600);
  } catch (err) {
    errorEl.textContent = "Could not reach server. Is the Flask app running?";
    errorEl.style.display = "block";
    btn.disabled = false;
    btnText.textContent = "Sign In";
  }
}

async function handleForgot(event) {
  event.preventDefault();

  const email = document.getElementById("forgot-email").value.trim();
  const errorEl = document.getElementById("forgot-error");
  const btn = document.getElementById("forgot-btn");
  const btnText = document.getElementById("forgot-btn-text");

  errorEl.style.display = "none";
  errorEl.textContent = "";
  btn.disabled = true;
  btnText.textContent = "Sending...";

  try {
    const response = await fetch("/api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });

    document.getElementById("forgot-email-display").textContent = email;
    showLoginScreen(3);
  } catch (err) {
    errorEl.textContent = "Could not reach server.";
    errorEl.style.display = "block";
  }

  btn.disabled = false;
  btnText.textContent = "Send Reset Link";
}

async function handleRequestInvite(event) {
  event.preventDefault();

  const name = document.getElementById("invite-name").value.trim();
  const email = document.getElementById("invite-email").value.trim();
  const errorEl = document.getElementById("invite-error");
  const btn = document.getElementById("invite-btn");
  const btnText = document.getElementById("invite-btn-text");

  errorEl.style.display = "none";
  errorEl.textContent = "";
  btn.disabled = true;
  btnText.textContent = "Sending...";

  try {
    const response = await fetch("/api/auth/request-invite", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name, email }),
    });

    const data = await response.json();

    if (!response.ok) {
      errorEl.textContent = data.error || "Something went wrong.";
      errorEl.style.display = "block";
      btn.disabled = false;
      btnText.textContent = "Send Request";
      return;
    }

    btnText.textContent = "Request Sent!";
    setTimeout(() => {
      showLoginScreen(1);
      btn.disabled = false;
      btnText.textContent = "Send Request";
    }, 2000); 
  } catch (err) {
    errorEl.textContent = "Could not reach server.";
    errorEl.style.display = "block";
    btn.disabled = false;
    btnText.textContent = "Send Request";
  }
}