/* NetSentry — Login page logic */

(function () {
  const TOKEN_KEY = "netsentry_token";
  const ROLE_KEY = "netsentry_role";
  const NAME_KEY = "netsentry_name";
  const USER_KEY = "netsentry_username";

  // If already logged in, verify token and redirect
  const existing = localStorage.getItem(TOKEN_KEY);
  if (existing) {
    fetch("/api/v1/auth/me", {
      headers: { Authorization: "Bearer " + existing },
    }).then(function (r) {
      if (r.ok) window.location.href = "/";
    });
  }

  var form = document.getElementById("login-form");
  var errorEl = document.getElementById("login-error");
  var btn = document.getElementById("login-btn");

  form.addEventListener("submit", function (e) {
    e.preventDefault();
    var username = document.getElementById("username").value.trim();
    var password = document.getElementById("password").value;

    btn.disabled = true;
    btn.textContent = "Signing in…";
    errorEl.style.display = "none";

    fetch("/api/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: username, password: password }),
    })
      .then(function (r) {
        if (!r.ok)
          return r.json().then(function (d) {
            throw new Error(d.detail || "Login failed");
          });
        return r.json();
      })
      .then(function (data) {
        localStorage.setItem(TOKEN_KEY, data.token);
        localStorage.setItem(ROLE_KEY, data.role);
        localStorage.setItem(NAME_KEY, data.full_name);
        localStorage.setItem(USER_KEY, data.username);
        window.location.href = "/";
      })
      .catch(function (err) {
        errorEl.textContent = err.message;
        errorEl.style.display = "block";
        btn.disabled = false;
        btn.textContent = "Sign In";
      });
  });
})();
