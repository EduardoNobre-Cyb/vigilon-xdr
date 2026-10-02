// Moved out of templates/change_password.html (was an inline <script>). Loaded as a classic
// script so its functions stay global for the onclick="..." handlers.
// Guard: must be logged in to reach this page
(function() {
  if (!localStorage.getItem('auth_token')) {
    window.location.replace('/login');
  }
})();
