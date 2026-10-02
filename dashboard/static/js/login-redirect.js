// Moved out of templates/login.html (was an inline <script>). Loaded as a classic
// script so its functions stay global for the onclick="..." handlers.
// If already logged in, send to the appropriate page
(function() {
  if (localStorage.getItem('auth_token')) {
    if (localStorage.getItem('must_change_password') === 'true') {
      window.location.replace('/change-password');
    } else {
      window.location.replace('/');
    }
  }
})();
