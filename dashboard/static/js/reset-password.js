var params = new URLSearchParams(window.location.search);
var resetToken = params.get('token');
var resetEmail = params.get('email');

if (!resetToken || !resetEmail) {
    document.getElementById("reset-screen-1").classList.remove("active");
    document.getElementById("reset-screen-3").classList.add("active");
}

function toggleResetPwd(inputId, btn) {
    var input = document.getElementById(inputId);
    var label = btn.querySelector(".eye-icon");
    if (input.type === "password") {
        input.type = "text";
        label.textContent = "hide";
    } else {
        input.type = "password";
        label.textContent = "show";
    }
}

var pwdInput = document.getElementById("new-password");
if (pwdInput) {
    pwdInput.addEventListener("input", function () {
        var pw = pwdInput.value;
        var score = 0;
        if (pw.length >= 8) score++;
        if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
        if (/\d/.test(pw)) score++;
        if (/[^a-zA-Z0-9]/.test(pw)) score++;

        var bars = document.querySelectorAll("#pwd-strength .pwd-strength-bar");
        var cls = score <= 1 ? "weak" : score <= 2 ? "medium" : "strong";
        bars.forEach(function (bar, i) {
            bar.className = "pwd-strength-bar" + (i < score ? " " + cls : "");
        });
    });
}

async function handleReset(event) {
    event.preventDefault();

    var newPw = document.getElementById("new-password").value;
    var confirmPw = document.getElementById("confirm-password").value;
    var errorEl = document.getElementById("reset-error");
    var btn = document.getElementById("reset-btn");
    var btnText = document.getElementById("reset-btn-text");

    errorEl.style.display = "none";

    if (newPw.length < 8) {
        errorEl.textContent = "⚠ New password must be at least 8 characters.";
        errorEl.style.display = "block";
        return;
    }
    if (newPw !== confirmPw) {
        errorEl.textContent = "⚠ New passwords do not match.";
        errorEl.style.display = "block";
        return;
    }

    btn.disabled = true;
    btnText.textContent = "Resetting...";

    try {
        var response = await fetch("/api/auth/reset-password", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                email: resetEmail,
                token: resetToken,
                new_password: newPw,
            }),
        });

        var data = await response.json();

        if (!response.ok) {
            if (data.error && data.error.toLowerCase().includes("expired")) {
                document.getElementById("reset-screen-1").classList.remove("active");
                document.getElementById("reset-screen-3").classList.add("active");
            } else {
                errorEl.textContent = data.error || "Reset failed.";
                errorEl.style.display = "block";
            }
            btn.disabled = false;
            btnText.textContent = "Reset Password";
            return;
        }

        document.getElementById("reset-screen-1").classList.remove("active");
        document.getElementById("reset-screen-2").classList.add("active");
    } catch (err) {
        errorEl.textContent = "⚠ An unexpected error occurred.";
        errorEl.style.display = "block";
        btn.disabled = false;
        btnText.textContent = "Reset Password";
    }
}