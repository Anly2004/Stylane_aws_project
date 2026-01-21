document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("loginForm");
  const err = document.getElementById("loginError");
  if (!form) return;

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    err.classList.add("hidden");
    const fd = new FormData(form);
    // Get selected role from URL parameter if present
    const urlParams = new URLSearchParams(window.location.search);
    const selectedRole = urlParams.get("role") || "";
    
    const payload = {
      email: (fd.get("email") || "").toString(),
      password: (fd.get("password") || "").toString(),
      selected_role: selectedRole,
    };

    const btn = form.querySelector("button[type=submit]");
    if (btn) btn.disabled = true;
    try {
      const data = await apiFetch("/login", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      window.location.href = data.redirect || "/";
    } catch (e2) {
      err.textContent = e2.message || "Login failed";
      err.classList.remove("hidden");
      if (btn) btn.disabled = false;
    }
  });
});

