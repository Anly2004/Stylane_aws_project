document.addEventListener("DOMContentLoaded", async () => {
  await loadInventory();
  await loadProducts();
  await loadRequests();
  bindRestockForm();
  bindAddProductModal();
});

async function loadInventory() {
  const table = document.getElementById("storeInventoryTable");
  if (!table) return;
  const tbody = table.querySelector("tbody");
  tbody.innerHTML = "";

  try {
    const data = await apiFetch("/api/store/inventory");
    (data.items || []).forEach((it) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${escapeHtml(it.product_name)}</td>
        <td class="muted small">${escapeHtml(it.category || "")}</td>
        <td>$${Number(it.price).toFixed(2)}</td>
        <td>
          <input class="input qtyInput" type="number" min="0" value="${it.quantity}" />
        </td>
        <td>
          <div class="row" style="gap: 6px;">
            <button class="btn btn--ghost">Save</button>
            <button class="btn btn--ghost" style="color: var(--danger); border-color: var(--danger);" data-inventory-id="${it.inventory_id}">Remove</button>
          </div>
        </td>
      `;

      const qtyInput = tr.querySelector("input");
      const saveBtn = tr.querySelectorAll("button")[0];
      const removeBtn = tr.querySelectorAll("button")[1];
      
      saveBtn.addEventListener("click", async () => {
        saveBtn.disabled = true;
        try {
          await apiFetch("/api/store/inventory/update", {
            method: "POST",
            body: JSON.stringify({
              inventory_id: it.inventory_id,
              quantity: Number(qtyInput.value || 0),
            }),
          });
          saveBtn.textContent = "Saved";
          setTimeout(() => (saveBtn.textContent = "Save"), 900);
        } catch (e) {
          alert(e.message || "Update failed");
        } finally {
          saveBtn.disabled = false;
        }
      });

      removeBtn.addEventListener("click", async () => {
        const confirmRemove = confirm("Do you want to:\n1. Set quantity to 0 (keep item)\n2. Remove item completely\n\nClick OK to remove completely, Cancel to set quantity to 0");
        const removeCompletely = confirmRemove;
        
        removeBtn.disabled = true;
        try {
          await apiFetch("/api/store/inventory/remove", {
            method: "POST",
            body: JSON.stringify({
              inventory_id: it.inventory_id,
              remove_completely: removeCompletely,
            }),
          });
          await loadInventory();
        } catch (e) {
          alert(e.message || "Remove failed");
          removeBtn.disabled = false;
        }
      });

      tbody.appendChild(tr);
    });
  } catch (e) {
    alert(e.message || "Failed to load inventory");
  }
}

async function loadProducts() {
  const select = document.getElementById("restockProduct");
  if (!select) return;
  select.innerHTML = "";
  try {
    const data = await apiFetch("/api/store/products");
    (data.products || []).forEach((p) => {
      const opt = document.createElement("option");
      opt.value = p.id;
      opt.textContent = `${p.name} (${p.category || "General"})`;
      select.appendChild(opt);
    });
  } catch (e) {
    alert(e.message || "Failed to load products");
  }
}

function bindRestockForm() {
  const form = document.getElementById("restockForm");
  if (!form) return;
  const msg = document.getElementById("restockMsg");
  const product = document.getElementById("restockProduct");
  const qty = document.getElementById("restockQty");

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    if (msg) msg.textContent = "Creating…";
    const btn = form.querySelector("button[type=submit]");
    if (btn) btn.disabled = true;
    try {
      const data = await apiFetch("/api/store/restock/create", {
        method: "POST",
        body: JSON.stringify({
          product_id: Number(product.value),
          requested_qty: Number(qty.value || 1),
        }),
      });
      if (msg) msg.textContent = `Created request #${data.id}`;
      await loadRequests(); // Refresh requests list
      setTimeout(() => {
        if (msg) msg.textContent = "";
      }, 1800);
    } catch (e2) {
      if (msg) msg.textContent = "";
      alert(e2.message || "Failed to create request");
    } finally {
      if (btn) btn.disabled = false;
    }
  });
}

function bindAddProductModal() {
  const addBtn = document.getElementById("addProductBtn");
  const formContainer = document.getElementById("addProductFormContainer");
  const cancelBtn = document.getElementById("cancelAddBtn");
  const form = document.getElementById("addProductForm");
  const errorDiv = document.getElementById("addProductError");
  const successDiv = document.getElementById("addProductSuccess");

  if (!addBtn || !formContainer) return;

  // Ensure form is hidden on page load
  formContainer.classList.add("hidden");

  // Function to hide form
  const hideForm = () => {
    formContainer.classList.add("hidden");
    form.reset();
    errorDiv.classList.add("hidden");
    successDiv.classList.add("hidden");
    successDiv.textContent = "";
  };

  // Show form when Add button is clicked
  addBtn.addEventListener("click", () => {
    formContainer.classList.remove("hidden");
    form.reset();
    errorDiv.classList.add("hidden");
    successDiv.classList.add("hidden");
  });

  // Hide form when Cancel is clicked
  if (cancelBtn) cancelBtn.addEventListener("click", hideForm);

  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      errorDiv.classList.add("hidden");
      successDiv.classList.add("hidden");

      const fd = new FormData(form);
      const payload = {
        name: (fd.get("name") || "").toString().trim(),
        category: (fd.get("category") || "").toString().trim(),
        price: parseFloat(fd.get("price") || 0),
        quantity: parseInt(fd.get("quantity") || 0),
      };

      if (!payload.name || !payload.category || payload.price < 0 || payload.quantity < 0) {
        errorDiv.textContent = "Please fill in all fields correctly";
        errorDiv.classList.remove("hidden");
        return;
      }

      const submitBtn = form.querySelector("button[type=submit]");
      if (submitBtn) submitBtn.disabled = true;

      try {
        const data = await apiFetch("/api/store/product/add", {
          method: "POST",
          body: JSON.stringify(payload),
        });

        successDiv.textContent = "Product added successfully!";
        successDiv.classList.remove("hidden");

        // Refresh inventory and products
        await loadInventory();
        await loadProducts();

        // Hide form after 2 seconds
        setTimeout(() => {
          hideForm();
        }, 2000);
      } catch (e2) {
        errorDiv.textContent = e2.message || "Failed to add product";
        errorDiv.classList.remove("hidden");
      } finally {
        if (submitBtn) submitBtn.disabled = false;
      }
    });
  }
}

async function loadRequests() {
  const table = document.getElementById("storeRequestsTable");
  if (!table) return;
  const tbody = table.querySelector("tbody");
  tbody.innerHTML = "";

  try {
    const data = await apiFetch("/api/store/requests");
    (data.items || []).forEach((r) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td>${r.id}</td>
        <td>${escapeHtml(r.product_name)}</td>
        <td>${r.requested_qty}</td>
        <td></td>
        <td>${escapeHtml(r.supplier)}</td>
        <td class="muted small">${new Date(r.created_at).toLocaleString()}</td>
      `;

      tr.children[3].appendChild(pill(r.status));

      tbody.appendChild(tr);
    });
  } catch (e) {
    // Silently fail if endpoint doesn't exist yet or other error
    console.error("Failed to load requests:", e);
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

