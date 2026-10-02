// Moved out of templates/dashboard.html (was an inline <script>). Loaded as a classic
// script so its functions stay global for the onclick="..." handlers.
// authFetch must be defined in <head> so all inline body scripts can use it.
function authFetch(url, options = {}) {
  const token = localStorage.getItem('auth_token');
  options.headers = {
    ...(options.headers || {}),
    'Authorization': `Bearer ${token}`,
    'Content-Type': 'application/json',
  };
  return fetch(url, options).then(res => {
    // If the token has expired or been invalidated, send back to login
    if (res.status === 401) {
      localStorage.removeItem('auth_token');
      localStorage.removeItem('user_role');
      localStorage.removeItem('user_name');
      window.location.replace('/login');
    }
    return res;
  });
}
