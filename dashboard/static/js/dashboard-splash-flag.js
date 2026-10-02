// Moved out of templates/dashboard.html (was an inline <script>). Loaded as a classic
// script so its functions stay global for the onclick="..." handlers.
// Post-login splash: login.html sets this flag after a successful sign-in.
// Marking <html> here, before the page draws, stops the dashboard flashing up first.
try {
  if (sessionStorage.getItem('vigilon_splash') === '1') {
    document.documentElement.classList.add('splash-pending');
  }
} catch (e) { /* storage blocked: just skip the splash */ }
