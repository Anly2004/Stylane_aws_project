from __future__ import annotations

import argparse
from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-only-change-me"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///stylelane.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(32), nullable=False)  # admin | store_manager | supplier
    store_id = db.Column(db.Integer, db.ForeignKey("stores.id"), nullable=True)
    admin_id = db.Column(db.String(32), nullable=True, index=True)  # Brand ID for Admin, links Store Manager to Admin
    brand_id = db.Column(db.String(32), nullable=True)  # Alias for admin_id (for Admin users)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Store(db.Model):
    __tablename__ = "stores"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    location = db.Column(db.String(200), nullable=True)
    admin_id = db.Column(db.String(32), nullable=False, index=True)  # Links store to Admin (Brand ID)


class Product(db.Model):
    __tablename__ = "products"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(120), nullable=True)
    price = db.Column(db.Float, nullable=False, default=0.0)
    supplier_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)


class Inventory(db.Model):
    __tablename__ = "inventory"
    id = db.Column(db.Integer, primary_key=True)
    store_id = db.Column(db.Integer, db.ForeignKey("stores.id"), nullable=False, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False, index=True)
    quantity = db.Column(db.Integer, nullable=False, default=0)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


class RestockRequest(db.Model):
    __tablename__ = "restock_requests"
    id = db.Column(db.Integer, primary_key=True)
    store_id = db.Column(db.Integer, db.ForeignKey("stores.id"), nullable=False, index=True)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False, index=True)
    supplier_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    requested_qty = db.Column(db.Integer, nullable=False)
    status = db.Column(
        db.String(32),
        nullable=False,
        default="pending",  # pending | accepted | shipped | rejected
    )
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)


def current_user() -> User | None:
    uid = session.get("user_id")
    if not uid:
        return None
    return db.session.get(User, uid)


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapper


def role_required(*roles: str):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if not session.get("user_id"):
                return redirect(url_for("login"))
            if session.get("role") not in roles:
                abort(403)
            return view(*args, **kwargs)

        return wrapper

    return decorator


@app.context_processor
def inject_user():
    return {"me": current_user(), "role": session.get("role")}


@app.get("/")
def index():
    if session.get("user_id"):
        role = session.get("role")
        if role == "admin":
            return redirect(url_for("admin_dashboard"))
        if role == "store_manager":
            return redirect(url_for("store_dashboard"))
        if role == "supplier":
            return redirect(url_for("supplier_dashboard"))
    return render_template("index.html")


@app.get("/home")
def home():
    """Alias for index, redirects to dashboard if logged in"""
    return redirect(url_for("index"))


@app.get("/about")
def about():
    return render_template("about.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        # Get selected role from URL parameter
        selected_role = request.args.get("role", "").strip()
        if selected_role in ["admin", "store_manager", "supplier"]:
            session["selected_role"] = selected_role
        return render_template("login.html", selected_role=session.get("selected_role"))

    data = request.get_json(silent=True) or request.form
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    selected_role = session.get("selected_role") or data.get("selected_role", "").strip()

    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({"ok": False, "error": "Invalid email or password"}), 401

    # Check if user's role matches the selected role
    if selected_role and user.role != selected_role:
        # Clear selected role from session
        session.pop("selected_role", None)
        role_names = {
            "admin": "Admin",
            "store_manager": "Store Manager",
            "supplier": "Supplier"
        }
        selected_name = role_names.get(selected_role, selected_role)
        user_role_name = role_names.get(user.role, user.role)
        return jsonify({
            "ok": False,
            "error": f"Access denied. You are logged in as {user_role_name}, but you selected {selected_name} role. Please select the correct role from the home page."
        }), 403

    # Clear selected role from session after successful validation
    session.pop("selected_role", None)

    # Auto-assign store_manager to first store if missing
    if user.role == "store_manager" and not user.store_id:
        first_store = Store.query.first()
        if not first_store:
            first_store = Store(name="Default Store", location="Main Location")
            db.session.add(first_store)
            db.session.flush()
        user.store_id = first_store.id
        db.session.commit()

    session["user_id"] = user.id
    session["role"] = user.role
    session["store_id"] = user.store_id
    session["admin_id"] = user.admin_id  # Store admin_id in session for filtering

    redirect_to = url_for("index")
    return jsonify({"ok": True, "redirect": redirect_to})


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        # If already logged in, redirect to appropriate dashboard
        if session.get("user_id"):
            return redirect(url_for("index"))
        return render_template("signup.html")

    data = request.get_json(silent=True) or request.form
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    
    # Default role to store_manager if not provided
    role = (data.get("role") or "store_manager").strip()

    # Validation
    if not name or not email or not password:
        return jsonify({"ok": False, "error": "All fields are required"}), 400

    # Validate role (defaults to store_manager)
    if role not in ["admin", "store_manager", "supplier"]:
        role = "store_manager"

    if len(password) < 6:
        return jsonify({"ok": False, "error": "Password must be at least 6 characters"}), 400

    # Check if email already exists
    existing = User.query.filter_by(email=email).first()
    if existing:
        return jsonify({"ok": False, "error": "Email already registered"}), 409

    # Create new user
    try:
        import secrets
        import string
        
        # Ensure database is migrated before creating user
        try:
            migrate_db()
        except Exception as migrate_error:
            print(f"Migration check: {migrate_error}")
            # Continue anyway - migration might have already run
        
        if role == "admin":
            # Admin signup - same as before (just generates Admin ID automatically)
            # Generate unique Admin ID (Brand ID)
            admin_id = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
            # Ensure uniqueness
            while User.query.filter_by(admin_id=admin_id, role="admin").first():
                admin_id = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
            
            user = User(name=name, email=email, role=role, admin_id=admin_id, brand_id=admin_id)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            
            return jsonify({"ok": True, "redirect": url_for("login"), "admin_id": admin_id})
        
        elif role == "store_manager":
            # Store Manager signup - requires Admin ID, Store Name, Store Location
            admin_id = (data.get("admin_id") or "").strip().upper()
            store_name = (data.get("store_name") or "").strip()
            store_location = (data.get("store_location") or "").strip()
            
            if not admin_id or not store_name:
                return jsonify({"ok": False, "error": "Admin ID and Store Name are required"}), 400
            
            # Verify Admin ID exists
            admin_user = User.query.filter_by(admin_id=admin_id, role="admin").first()
            if not admin_user:
                return jsonify({"ok": False, "error": "Invalid Admin ID. Please check and try again."}), 400
            
            # Create store
            store = Store(name=store_name, location=store_location, admin_id=admin_id)
            db.session.add(store)
            db.session.flush()
            
            # Create store manager linked to admin_id and store
            user = User(name=name, email=email, role=role, admin_id=admin_id, store_id=store.id)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            
            return jsonify({"ok": True, "redirect": url_for("login"), "store_id": store.id})
        
        else:
            # Supplier signup - same as before (no extra fields)
            user = User(name=name, email=email, role=role)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
        
        return jsonify({"ok": True, "redirect": url_for("login")})
    except Exception as e:
        db.session.rollback()
        # Log the actual error for debugging
        import traceback
        error_msg = str(e)
        print(f"Signup error: {error_msg}")
        print(traceback.format_exc())
        
        # Provide user-friendly error message
        if "no such column" in error_msg.lower() or "admin_id" in error_msg.lower() or "brand_id" in error_msg.lower():
            return jsonify({
                "ok": False, 
                "error": "Database needs to be updated. Please run: python app.py --init-db or contact administrator."
            }), 500
        
        return jsonify({"ok": False, "error": "Registration failed. Please try again."}), 500


@app.post("/logout")
def logout():
    session.clear()
    return jsonify({"ok": True, "redirect": url_for("index")})


@app.get("/admin")
@role_required("admin")
def admin_dashboard():
    return render_template("admin_dashboard.html")


@app.get("/store")
@role_required("store_manager")
def store_dashboard():
    return render_template("store_dashboard.html")


@app.get("/supplier")
@role_required("supplier")
def supplier_dashboard():
    return render_template("supplier_dashboard.html")


# -----------------------
# JSON APIs (used by JS)
# -----------------------


@app.get("/api/admin/overview")
@role_required("admin")
def api_admin_overview():
    admin_id = session.get("admin_id")
    if not admin_id:
        # Get admin_id from current user
        user = current_user()
        if user and user.role == "admin":
            admin_id = user.admin_id
            session["admin_id"] = admin_id
        else:
            return jsonify({"ok": False, "error": "Admin ID not found"}), 400
    
    # Filter all queries by admin_id
    stores_count = Store.query.filter_by(admin_id=admin_id).count()
    store_managers = User.query.filter_by(role="store_manager", admin_id=admin_id).all()
    users_count = len(store_managers) + 1  # Store managers + 1 admin
    
    # Count products added by store managers (products in inventory of stores under this admin)
    stores_under_admin = Store.query.filter_by(admin_id=admin_id).all()
    store_ids = [s.id for s in stores_under_admin]
    products_count = db.session.query(Product).join(Inventory).filter(
        Inventory.store_id.in_(store_ids) if store_ids else False
    ).distinct().count() if store_ids else 0
    
    requests_count = RestockRequest.query.join(Store).filter(Store.admin_id == admin_id).count()

    # Get stores under this admin
    stores = Store.query.filter_by(admin_id=admin_id).all()
    stores_list = []
    for store in stores:
        manager = User.query.filter_by(store_id=store.id, role="store_manager").first()
        stores_list.append({
            "id": store.id,
            "name": store.name,
            "location": store.location,
            "manager": manager.name if manager else "Unassigned",
        })

    recent_requests = (
        db.session.query(RestockRequest, Store, Product, User)
        .join(Store, Store.id == RestockRequest.store_id)
        .join(Product, Product.id == RestockRequest.product_id)
        .outerjoin(User, User.id == RestockRequest.supplier_id)
        .filter(Store.admin_id == admin_id)
        .order_by(RestockRequest.created_at.desc())
        .limit(10)
        .all()
    )

    rr = []
    for req, store, product, supplier in recent_requests:
        rr.append(
            {
                "id": req.id,
                "store_id": store.id,
                "store": store.name,
                "store_location": store.location,
                "product": product.name,
                "requested_qty": req.requested_qty,
                "status": req.status,
                "supplier": supplier.name if supplier else "Unassigned",
                "created_at": req.created_at.isoformat(),
            }
        )

    return jsonify(
        {
            "ok": True,
            "admin_id": admin_id,  # Include Admin ID in response
            "counts": {
                "users": users_count,
                "stores": stores_count,
                "products": products_count,
                "requests": requests_count,
            },
            "stores": stores_list,
            "recent_requests": rr,
        }
    )


def get_store_manager_store_id():
    """Get store_id for store_manager, auto-assign if missing."""
    store_id = session.get("store_id")
    if store_id:
        return store_id
    
    # Check user object from database
    user = current_user()
    if user and user.role == "store_manager":
        if user.store_id:
            # Update session
            session["store_id"] = user.store_id
            return user.store_id
        else:
            # Auto-assign to first store
            first_store = Store.query.first()
            if not first_store:
                first_store = Store(name="Default Store", location="Main Location")
                db.session.add(first_store)
                db.session.flush()
            user.store_id = first_store.id
            session["store_id"] = first_store.id
            db.session.commit()
            return first_store.id
    
    return None


@app.get("/api/store/inventory")
@role_required("store_manager")
def api_store_inventory_list():
    store_id = get_store_manager_store_id()
    if not store_id:
        return jsonify({"ok": False, "error": "Store not assigned"}), 400

    # Ensure store manager can only access their own store
    user = current_user()
    if user.store_id != store_id:
        return jsonify({"ok": False, "error": "Unauthorized access"}), 403

    rows = (
        db.session.query(Inventory, Product)
        .join(Product, Product.id == Inventory.product_id)
        .filter(Inventory.store_id == store_id)
        .order_by(Product.name.asc())
        .all()
    )
    items = []
    for inv, prod in rows:
        items.append(
            {
                "inventory_id": inv.id,
                "product_id": prod.id,
                "product_name": prod.name,
                "category": prod.category,
                "price": prod.price,
                "quantity": inv.quantity,
                "updated_at": inv.updated_at.isoformat(),
            }
        )

    return jsonify({"ok": True, "items": items})


@app.post("/api/store/inventory/update")
@role_required("store_manager")
def api_store_inventory_update():
    store_id = get_store_manager_store_id()
    if not store_id:
        return jsonify({"ok": False, "error": "Store not assigned"}), 400

    # Ensure store manager can only access their own store
    user = current_user()
    if user.store_id != store_id:
        return jsonify({"ok": False, "error": "Unauthorized access"}), 403

    data = request.get_json(force=True)
    inventory_id = int(data.get("inventory_id"))
    quantity = int(data.get("quantity"))

    inv = Inventory.query.filter_by(id=inventory_id, store_id=store_id).first()
    if not inv:
        return jsonify({"ok": False, "error": "Inventory item not found"}), 404

    inv.quantity = max(0, quantity)
    inv.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True})


@app.post("/api/store/inventory/remove")
@role_required("store_manager")
def api_store_inventory_remove():
    store_id = get_store_manager_store_id()
    if not store_id:
        return jsonify({"ok": False, "error": "Store not assigned"}), 400

    # Ensure store manager can only access their own store
    user = current_user()
    if user.store_id != store_id:
        return jsonify({"ok": False, "error": "Unauthorized access"}), 403

    data = request.get_json(force=True)
    inventory_id = int(data.get("inventory_id"))
    remove_completely = data.get("remove_completely", False)

    inv = Inventory.query.filter_by(id=inventory_id, store_id=store_id).first()
    if not inv:
        return jsonify({"ok": False, "error": "Inventory item not found"}), 404

    if remove_completely:
        db.session.delete(inv)
    else:
        # Just set quantity to 0
        inv.quantity = 0
        inv.updated_at = datetime.utcnow()
    
    db.session.commit()
    return jsonify({"ok": True})


@app.get("/api/store/products")
@role_required("store_manager")
def api_store_products():
    products = Product.query.order_by(Product.name.asc()).all()
    return jsonify(
        {
            "ok": True,
            "products": [
                {"id": p.id, "name": p.name, "category": p.category, "price": p.price}
                for p in products
            ],
        }
    )


@app.post("/api/store/product/add")
@role_required("store_manager")
def api_store_product_add():
    store_id = get_store_manager_store_id()
    if not store_id:
        return jsonify({"ok": False, "error": "Store not assigned"}), 400

    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    category = (data.get("category") or "").strip()
    price = float(data.get("price") or 0)
    quantity = int(data.get("quantity") or 0)

    if not name or not category:
        return jsonify({"ok": False, "error": "Name and category are required"}), 400

    if price < 0:
        return jsonify({"ok": False, "error": "Price must be non-negative"}), 400

    if quantity < 0:
        return jsonify({"ok": False, "error": "Quantity must be non-negative"}), 400

    try:
        # Create new product
        product = Product(name=name, category=category, price=price, supplier_id=None)
        db.session.add(product)
        db.session.flush()

        # Add to inventory
        inventory = Inventory(
            store_id=store_id,
            product_id=product.id,
            quantity=quantity,
        )
        db.session.add(inventory)
        db.session.commit()

        return jsonify({"ok": True, "id": product.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({"ok": False, "error": "Failed to add product. Please try again."}), 500


@app.post("/api/store/restock/create")
@role_required("store_manager")
def api_store_restock_create():
    store_id = get_store_manager_store_id()
    if not store_id:
        return jsonify({"ok": False, "error": "Store not assigned"}), 400

    # Ensure store manager can only create requests for their own store
    user = current_user()
    if user.store_id != store_id:
        return jsonify({"ok": False, "error": "Unauthorized access"}), 403

    data = request.get_json(force=True)
    product_id = int(data.get("product_id"))
    requested_qty = int(data.get("requested_qty"))
    requested_qty = max(1, requested_qty)

    product = db.session.get(Product, product_id)
    if not product:
        return jsonify({"ok": False, "error": "Product not found"}), 404

    # Get store details for request
    store = db.session.get(Store, store_id)
    if not store:
        return jsonify({"ok": False, "error": "Store not found"}), 404

    # Use product's supplier_id, but allow None (unassigned requests can be seen by all suppliers)
    supplier_id = product.supplier_id if product.supplier_id else None

    req = RestockRequest(
        store_id=store_id,
        product_id=product_id,
        supplier_id=supplier_id,
        requested_qty=requested_qty,
        status="pending",
    )
    db.session.add(req)
    db.session.commit()
    return jsonify({
        "ok": True, 
        "id": req.id,
        "store_id": store.id,
        "store_name": store.name,
        "store_location": store.location,
    })


@app.get("/api/store/requests")
@role_required("store_manager")
def api_store_requests():
    store_id = get_store_manager_store_id()
    if not store_id:
        return jsonify({"ok": False, "error": "Store not assigned"}), 400

    # Ensure store manager can only access their own store requests
    user = current_user()
    if user.store_id != store_id:
        return jsonify({"ok": False, "error": "Unauthorized access"}), 403

    # Get all requests for this store
    rows = (
        db.session.query(RestockRequest, Product, User)
        .join(Product, Product.id == RestockRequest.product_id)
        .outerjoin(User, User.id == RestockRequest.supplier_id)
        .filter(RestockRequest.store_id == store_id)
        .order_by(RestockRequest.created_at.desc())
        .all()
    )
    
    items = []
    for req, product, supplier in rows:
        items.append({
            "id": req.id,
            "product_id": product.id,
            "product_name": product.name,
            "requested_qty": req.requested_qty,
            "status": req.status,
            "supplier": supplier.name if supplier else "Unassigned",
            "created_at": req.created_at.isoformat(),
            "updated_at": req.updated_at.isoformat(),
        })
    
    return jsonify({"ok": True, "items": items})


@app.get("/api/supplier/requests")
@role_required("supplier")
def api_supplier_requests():
    supplier_id = session.get("user_id")
    # Show ALL requests so suppliers can see and decide which ones to accept
    # Suppliers can accept any request, which will assign it to them
    rows = (
        db.session.query(RestockRequest, Store, Product)
        .join(Store, Store.id == RestockRequest.store_id)
        .join(Product, Product.id == RestockRequest.product_id)
        .filter(RestockRequest.status != "rejected")  # Don't show rejected requests
        .order_by(RestockRequest.created_at.desc())
        .all()
    )
    items = []
    for req, store, prod in rows:
        items.append(
            {
                "id": req.id,
                "store_id": store.id,
                "store": store.name,
                "store_location": store.location,
                "product": prod.name,
                "requested_qty": req.requested_qty,
                "status": req.status,
                "created_at": req.created_at.isoformat(),
            }
        )
    return jsonify({"ok": True, "items": items})


@app.post("/api/supplier/requests/update")
@role_required("supplier")
def api_supplier_requests_update():
    supplier_id = session.get("user_id")
    data = request.get_json(force=True)
    request_id = int(data.get("id"))
    status = (data.get("status") or "").strip().lower()

    if status not in {"accepted", "rejected", "shipped"}:
        return jsonify({"ok": False, "error": "Invalid status"}), 400

    # Suppliers can accept/update any pending request (except rejected ones)
    # When accepting a request, assign it to this supplier
    req = RestockRequest.query.filter(RestockRequest.id == request_id).first()
    
    if not req:
        return jsonify({"ok": False, "error": "Request not found"}), 404

    # If accepting a request (accepted or shipped), assign it to this supplier
    # This allows suppliers to "claim" requests by accepting them
    if status in {"accepted", "shipped"}:
        req.supplier_id = supplier_id

    req.status = status
    req.updated_at = datetime.utcnow()
    db.session.commit()
    return jsonify({"ok": True})


# -----------------------
# CLI helpers
# -----------------------


def init_db() -> None:
    with app.app_context():
        db.create_all()
        # Migrate existing tables if needed
        migrate_db()


def migrate_db() -> None:
    """Add new columns to existing tables if they don't exist."""
    from sqlalchemy import inspect, text
    
    inspector = inspect(db.engine)
    conn = db.engine.connect()
    
    try:
        # Check if admin_id exists in users table
        user_columns = [col['name'] for col in inspector.get_columns('users')]
        if 'admin_id' not in user_columns:
            print("Adding admin_id column to users table...")
            conn.execute(text("ALTER TABLE users ADD COLUMN admin_id VARCHAR(32)"))
            conn.commit()
        
        if 'brand_id' not in user_columns:
            print("Adding brand_id column to users table...")
            conn.execute(text("ALTER TABLE users ADD COLUMN brand_id VARCHAR(32)"))
            conn.commit()
        
        # Check if admin_id exists in stores table
        store_columns = [col['name'] for col in inspector.get_columns('stores')]
        if 'location' not in store_columns:
            print("Adding location column to stores table...")
            conn.execute(text("ALTER TABLE stores ADD COLUMN location VARCHAR(200)"))
            conn.commit()
        
        if 'admin_id' not in store_columns:
            print("Adding admin_id column to stores table...")
            # First, make it nullable temporarily
            conn.execute(text("ALTER TABLE stores ADD COLUMN admin_id VARCHAR(32)"))
            conn.commit()
            # Set default admin_id for existing stores (if any)
            result = conn.execute(text("SELECT admin_id FROM users WHERE role = 'admin' LIMIT 1"))
            admin_row = result.fetchone()
            if admin_row and admin_row[0]:
                default_admin_id = admin_row[0]
                conn.execute(text(f"UPDATE stores SET admin_id = '{default_admin_id}' WHERE admin_id IS NULL"))
                conn.commit()
            else:
                print("Warning: No admin found. Existing stores may need manual admin_id assignment.")
    except Exception as e:
        print(f"Migration note: {e}")
        conn.rollback()
    finally:
        conn.close()


def seed_db() -> None:
    with app.app_context():
        if User.query.first():
            return

        import secrets
        import string
        
        # Generate Admin ID
        admin_id = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))

        admin = User(
            name="Admin",
            email="admin@stylelane.local",
            role="admin",
            store_id=None,
            admin_id=admin_id,
            brand_id=admin_id,
        )
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.flush()

        main_store = Store(name="StyleLane - Main Store", location="City Center", admin_id=admin_id)
        db.session.add(main_store)
        db.session.flush()

        supplier = User(
            name="Supplier",
            email="supplier@stylelane.local",
            role="supplier",
            store_id=None,
        )
        supplier.set_password("supplier123")

        manager = User(
            name="Store Manager",
            email="manager@stylelane.local",
            role="store_manager",
            store_id=main_store.id,
            admin_id=admin_id,
        )
        manager.set_password("manager123")

        db.session.add_all([supplier, manager])
        db.session.flush()

        p1 = Product(
            name="Classic Denim Jacket",
            category="Outerwear",
            price=79.99,
            supplier_id=supplier.id,
        )
        p2 = Product(
            name="Cotton T-Shirt",
            category="Basics",
            price=19.99,
            supplier_id=supplier.id,
        )
        p3 = Product(
            name="Slim Fit Chinos",
            category="Bottoms",
            price=49.99,
            supplier_id=supplier.id,
        )
        db.session.add_all([p1, p2, p3])
        db.session.flush()

        inv = [
            Inventory(store_id=main_store.id, product_id=p1.id, quantity=12),
            Inventory(store_id=main_store.id, product_id=p2.id, quantity=35),
            Inventory(store_id=main_store.id, product_id=p3.id, quantity=8),
        ]
        db.session.add_all(inv)
        db.session.commit()
        print(f"Demo Admin ID (Brand ID): {admin_id}")


def parse_args():
    parser = argparse.ArgumentParser(description="StyleLane local app")
    parser.add_argument("--init-db", action="store_true", help="Create sqlite tables")
    parser.add_argument("--migrate", action="store_true", help="Migrate existing database (add new columns)")
    parser.add_argument("--seed", action="store_true", help="Seed demo data")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.init_db:
        init_db()
        print("DB initialized.")
    if args.migrate:
        with app.app_context():
            migrate_db()
        print("DB migrated.")
    if args.seed:
        seed_db()
        print("DB seeded.")
    if not (args.init_db or args.migrate or args.seed):
        # Auto-migrate on startup if needed
        with app.app_context():
            try:
                migrate_db()
            except:
                pass
        app.run(debug=True)

