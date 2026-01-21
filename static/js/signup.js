document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("signupForm");
  const err = document.getElementById("signupError");
  const success = document.getElementById("signupSuccess");
  const storeManagerFields = document.getElementById("storeManagerFields");
  if (!form) return;

  // Check if role is selected from URL
  const urlParams = new URLSearchParams(window.location.search);
  const role = urlParams.get("role") || "";

  // Update description based on role
  const descEl = document.getElementById("signupDescription");
  if (descEl) {
    if (role === "store_manager") {
      descEl.textContent = "Register as a Store Manager. You'll need your Admin ID (Brand ID) from your brand administrator.";
    } else if (role === "admin") {
      descEl.textContent = "Register as an Admin. A unique Brand ID will be generated for you.";
    } else if (role === "supplier") {
      descEl.textContent = "Register as a Supplier to manage restock requests.";
    } else {
      descEl.textContent = "Join StyleLane to manage your inventory and supplies.";
    }
  }

  // Only show store manager fields if role is explicitly "store_manager"
  // Admin and Supplier signups remain unchanged - no extra fields shown
  if (role === "store_manager" && storeManagerFields) {
    storeManagerFields.classList.remove("hidden");
    // Make store manager fields required
    const adminIdField = storeManagerFields.querySelector('input[name="admin_id"]');
    const storeNameField = storeManagerFields.querySelector('input[name="store_name"]');
    if (adminIdField) adminIdField.required = true;
    if (storeNameField) storeNameField.required = true;
  }

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    err.classList.add("hidden");
    success.classList.add("hidden");

    const fd = new FormData(form);
    const password = (fd.get("password") || "").toString();
    const confirmPassword = (fd.get("confirm_password") || "").toString();

    // Client-side validation
    if (password !== confirmPassword) {
      err.textContent = "Passwords do not match";
      err.classList.remove("hidden");
      return;
    }

    if (password.length < 6) {
      err.textContent = "Password must be at least 6 characters";
      err.classList.remove("hidden");
      return;
    }

    // Determine role: from URL param, or default to store_manager for backward compatibility
    let finalRole = role || "store_manager";
    
    const payload = {
      name: (fd.get("name") || "").toString().trim(),
      email: (fd.get("email") || "").toString().trim().toLowerCase(),
      password: password,
      role: finalRole,
    };

    // Only add store manager specific fields if role is explicitly "store_manager"
    // Admin and Supplier signups don't require these fields
    if (role === "store_manager") {
      payload.admin_id = (fd.get("admin_id") || "").toString().trim().toUpperCase();
      payload.store_name = (fd.get("store_name") || "").toString().trim();
      payload.store_location = (fd.get("store_location") || "").toString().trim();
    }

    if (!payload.name || !payload.email) {
      err.textContent = "Please fill in all fields";
      err.classList.remove("hidden");
      return;
    }

    // Validate store manager fields only when role is explicitly "store_manager"
    if (role === "store_manager") {
      if (!payload.admin_id || !payload.store_name) {
        err.textContent = "Admin ID and Store Name are required";
        err.classList.remove("hidden");
        return;
      }
    }

    const btn = form.querySelector("button[type=submit]");
    if (btn) btn.disabled = true;

    try {
      const data = await apiFetch("/signup", {
        method: "POST",
        body: JSON.stringify(payload),
      });

      if (data.admin_id) {
        success.innerHTML = `Account created successfully!<br><strong>Your Admin ID (Brand ID): ${data.admin_id}</strong><br>Please save this ID for Store Manager registrations.<br>Redirecting to login...`;
      } else if (data.store_id) {
        success.innerHTML = `Account created successfully!<br><strong>Store ID: ${data.store_id}</strong><br>Redirecting to login...`;
      } else {
        success.textContent = "Account created successfully! Redirecting to login...";
      }
      success.classList.remove("hidden");
      
      // Redirect to login after 4 seconds (to allow user to save Admin ID)
      setTimeout(() => {
        window.location.href = data.redirect || "/login";
      }, 4000);
    } catch (e2) {
      err.textContent = e2.message || "Signup failed. Please try again.";
      err.classList.remove("hidden");
      if (btn) btn.disabled = false;
    }
  });
});
