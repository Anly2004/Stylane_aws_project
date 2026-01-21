async function apiFetch(url, options = {}) {
  const resp = await fetch(url, {
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    credentials: "same-origin",
    ...options,
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    const msg = data?.error || `Request failed (${resp.status})`;
    throw new Error(msg);
  }
  return data;
}

function $(sel) {
  return document.querySelector(sel);
}

function pill(status) {
  const s = (status || "").toLowerCase();
  const span = document.createElement("span");
  span.className = "pill";
  span.textContent = s || "unknown";
  if (s === "shipped") span.classList.add("pill--good");
  else if (s === "pending" || s === "accepted") span.classList.add("pill--warn");
  else if (s === "rejected") span.classList.add("pill--bad");
  return span;
}

async function bindLogout() {
  const btn = $("#logoutBtn");
  if (!btn) return;
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    try {
      const data = await apiFetch("/logout", { method: "POST" });
      window.location.href = data.redirect || "/login";
    } catch (e) {
      btn.disabled = false;
      alert(e.message || "Logout failed");
    }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  bindLogout();
});

