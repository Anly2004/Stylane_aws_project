document.addEventListener("DOMContentLoaded", async () => {
  await loadOverview();
  
  // Setup products stat click
  const productsStat = document.getElementById("productsStat");
  const productsSection = document.getElementById("productsSection");
  
  if (productsStat && productsSection) {
    productsStat.addEventListener("click", async () => {
      if (productsSection.style.display === "none") {
        productsSection.style.display = "block";
        await loadProducts();
      } else {
        productsSection.style.display = "none";
      }
    });
  }
  
  // Setup copy button
  const copyBtn = document.getElementById("copyAdminIdBtn");
  const adminIdDisplay = document.getElementById("adminIdDisplay");
  
  if (copyBtn && adminIdDisplay) {
    copyBtn.addEventListener("click", async () => {
      const adminId = adminIdDisplay.textContent.trim();
      if (adminId && adminId !== "—") {
        try {
          await navigator.clipboard.writeText(adminId);
          const originalText = copyBtn.innerHTML;
          copyBtn.innerHTML = `
            <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <path d="M13.5 5.5L7.5 11.5 4 8"></path>
            </svg>
            Copied!
          `;
          copyBtn.style.color = "#10b981";
          copyBtn.style.borderColor = "#10b981";
          
          setTimeout(() => {
            copyBtn.innerHTML = originalText;
            copyBtn.style.color = "";
            copyBtn.style.borderColor = "";
          }, 2000);
        } catch (err) {
          // Fallback for older browsers
          const textArea = document.createElement("textarea");
          textArea.value = adminId;
          textArea.style.position = "fixed";
          textArea.style.opacity = "0";
          document.body.appendChild(textArea);
          textArea.select();
          try {
            document.execCommand("copy");
            const originalText = copyBtn.innerHTML;
            copyBtn.innerHTML = `
              <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M13.5 5.5L7.5 11.5 4 8"></path>
              </svg>
              Copied!
            `;
            copyBtn.style.color = "#10b981";
            copyBtn.style.borderColor = "#10b981";
            
            setTimeout(() => {
              copyBtn.innerHTML = originalText;
              copyBtn.style.color = "";
              copyBtn.style.borderColor = "";
            }, 2000);
          } catch (e) {
            alert("Failed to copy. Please copy manually: " + adminId);
          }
          document.body.removeChild(textArea);
        }
      }
    });
  }
});

async function loadOverview() {
  try {
    const data = await apiFetch("/api/admin/overview");
    const counts = data.counts || {};
    
    // Display Admin ID
    const adminIdDisplay = document.getElementById("adminIdDisplay");
    if (adminIdDisplay && data.admin_id) {
      adminIdDisplay.textContent = data.admin_id;
    }
    
    const countsWrap = document.getElementById("adminCounts");
    if (countsWrap) {
      countsWrap.querySelectorAll("[data-key]").forEach((el) => {
        const key = el.getAttribute("data-key");
        el.textContent = counts[key] ?? "—";
      });
    }

    // Load stores table
    const storesTable = document.getElementById("adminStoresTable");
    if (storesTable) {
      const storesTbody = storesTable.querySelector("tbody");
      storesTbody.innerHTML = "";
      
      (data.stores || []).forEach((store) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${store.id}</td>
          <td>${escapeHtml(store.name)}</td>
          <td>${escapeHtml(store.location || "—")}</td>
          <td>${escapeHtml(store.manager)}</td>
        `;
        storesTbody.appendChild(tr);
      });
    }

    // Load recent requests table
    const table = document.getElementById("adminRecentRequests");
    if (table) {
      const tbody = table.querySelector("tbody");
      tbody.innerHTML = "";

      (data.recent_requests || []).forEach((r) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${r.id}</td>
          <td>${escapeHtml(r.store)}<br><small class="muted">ID: ${r.store_id}, ${escapeHtml(r.store_location || "")}</small></td>
          <td>${escapeHtml(r.product)}</td>
          <td>${r.requested_qty}</td>
          <td></td>
          <td>${escapeHtml(r.supplier)}</td>
          <td class="muted small">${new Date(r.created_at).toLocaleString()}</td>
        `;
        tr.children[4].appendChild(pill(r.status));
        tbody.appendChild(tr);
      });
    }
  } catch (e) {
    alert(e.message || "Failed to load overview");
  }
}

async function loadProducts() {
  try {
    const data = await apiFetch("/api/admin/products");
    const productsTable = document.getElementById("adminProductsTable");
    if (productsTable) {
      const tbody = productsTable.querySelector("tbody");
      tbody.innerHTML = "";
      
      (data.products || []).forEach((product) => {
        const tr = document.createElement("tr");
        const storesHtml = product.stores.map(store => 
          `${escapeHtml(store.store_name)} (Qty: ${store.quantity})`
        ).join("<br>");
        
        tr.innerHTML = `
          <td>${product.id}</td>
          <td>${escapeHtml(product.name)}</td>
          <td>${escapeHtml(product.category || "—")}</td>
          <td>$${Number(product.price).toFixed(2)}</td>
          <td>${storesHtml}</td>
        `;
        tbody.appendChild(tr);
      });
    }
  } catch (e) {
    alert(e.message || "Failed to load products");
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

