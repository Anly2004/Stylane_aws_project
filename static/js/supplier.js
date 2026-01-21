document.addEventListener("DOMContentLoaded", async () => {
  await loadRequests();
});

async function loadRequests() {
  const table = document.getElementById("supplierRequestsTable");
  if (!table) return;
  const tbody = table.querySelector("tbody");
  tbody.innerHTML = "";

  try {
    const data = await apiFetch("/api/supplier/requests");
    (data.items || []).forEach((r) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${r.id}</td>
        <td>${escapeHtml(r.store)}<br><small class="muted">ID: ${r.store_id}</small></td>
        <td>${escapeHtml(r.store_location || "—")}</td>
        <td>${escapeHtml(r.product)}</td>
        <td>${r.requested_qty}</td>
        <td></td>
        <td>
          <div class="row">
            <select class="input supplier-status-select">
              <option value="accepted" style="background:#000;color:#fff">accepted</option>
              <option value="shipped" style="background:#000;color:#fff">shipped</option>
              <option value="rejected" style="background:#000;color:#fff">rejected</option>
            </select>
            <button class="btn btn--ghost">Update</button>
          </div>
        </td>
      `;

      tr.children[5].appendChild(pill(r.status));

      const select = tr.querySelector("select");
      select.value = r.status === "pending" ? "accepted" : r.status;
      const btn = tr.querySelector("button");

      btn.addEventListener("click", async () => {
        btn.disabled = true;
        try {
          await apiFetch("/api/supplier/requests/update", {
            method: "POST",
            body: JSON.stringify({ id: r.id, status: select.value }),
          });
          await loadRequests();
        } catch (e) {
          alert(e.message || "Update failed");
        } finally {
          btn.disabled = false;
        }
      });

      tbody.appendChild(tr);
    });
  } catch (e) {
    alert(e.message || "Failed to load requests");
  }
}

function escapeHtml(str) {
  return String(str || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

