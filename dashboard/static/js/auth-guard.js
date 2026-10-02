// Moved out of templates/dashboard.html (was an inline <script>). Loaded as a classic
// script so its functions stay global for the onclick="..." handlers.
// Auth guard — runs before anything renders.
// If no token, redirect to login. If password change is required, redirect there first.
(function() {
  if (!localStorage.getItem('auth_token')) {
    window.location.replace('/login');
  } else if (localStorage.getItem('must_change_password') === 'true') {
    window.location.replace('/change-password');
  }
})();
