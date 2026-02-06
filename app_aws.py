from __future__ import annotations

import argparse
import secrets
import string
import uuid
from datetime import datetime
from functools import wraps
<<<<<<< HEAD
from decimal import Decimal
=======
>>>>>>> 36a7adf28225fe68e4484914302ffcb424f92496

import boto3
from botocore.exceptions import ClientError
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
from werkzeug.security import check_password_hash, generate_password_hash

# -----------------------
# AWS CONFIGURATION
# -----------------------
REGION = 'us-east-1'

# DynamoDB table names
TABLE_USERS = 'stylelane_users'
TABLE_STORES = 'stylelane_stores'
TABLE_PRODUCTS = 'stylelane_products'
TABLE_INVENTORY = 'stylelane_inventory'
TABLE_RESTOCK_REQUESTS = 'stylelane_restock_requests'

# SNS Topic ARN (must be configured in AWS)
# IMPORTANT: Update this with your actual SNS Topic ARN
# You can create a topic in AWS SNS and use its ARN here
SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:123456789012:stylelane-notifications'

# Initialize AWS services
dynamodb = boto3.resource('dynamodb', region_name=REGION)
sns = boto3.client('sns', region_name=REGION)

# Flask app
app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-only-change-me"


# -----------------------
# SNS NOTIFICATION HELPER
# -----------------------
def send_notification(subject: str, message: str) -> None:
    """Send SNS notification."""
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )
    except ClientError as e:
        print(f"SNS notification error: {e}")
        # Continue execution even if notification fails


# -----------------------
# DYNAMODB HELPER FUNCTIONS
# -----------------------
def get_table(table_name: str):
    """Get DynamoDB table resource."""
    return dynamodb.Table(table_name)


<<<<<<< HEAD
def _convert_floats_to_decimal(data):
    """
    Recursively convert float values to Decimal for DynamoDB.
    DynamoDB (and moto) do not accept plain Python floats.
    """
    if isinstance(data, float):
        return Decimal(str(data))
    if isinstance(data, dict):
        return {k: _convert_floats_to_decimal(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_convert_floats_to_decimal(v) for v in data]
    return data


=======
>>>>>>> 36a7adf28225fe68e4484914302ffcb424f92496
def get_user_by_id(user_id: str) -> dict | None:
    """Get user by ID."""
    try:
        table = get_table(TABLE_USERS)
        response = table.get_item(Key={'id': user_id})
        return response.get('Item')
    except ClientError:
        return None


def get_user_by_email(email: str) -> dict | None:
    """Get user by email (using GSI)."""
    try:
        table = get_table(TABLE_USERS)
        response = table.query(
            IndexName='email-index',
            KeyConditionExpression='email = :email',
            ExpressionAttributeValues={':email': email}
        )
        items = response.get('Items', [])
        return items[0] if items else None
    except ClientError:
        # Fallback to scan if GSI doesn't exist
        try:
            response = table.scan(
                FilterExpression='email = :email',
                ExpressionAttributeValues={':email': email}
            )
            items = response.get('Items', [])
            return items[0] if items else None
        except ClientError:
            return None


def create_user(user_data: dict) -> str:
    """Create a new user and return user ID."""
    table = get_table(TABLE_USERS)
    user_id = str(uuid.uuid4())
    user_data['id'] = user_id
    user_data['created_at'] = datetime.utcnow().isoformat()
    table.put_item(Item=user_data)
    return user_id


def update_user(user_id: str, updates: dict) -> None:
    """Update user attributes."""
    table = get_table(TABLE_USERS)
    update_expr = "SET " + ", ".join([f"{k} = :{k}" for k in updates.keys()])
    expr_values = {f":{k}": v for k, v in updates.items()}
    
    table.update_item(
        Key={'id': user_id},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=expr_values
    )


def get_store_by_id(store_id: str) -> dict | None:
    """Get store by ID."""
    try:
        table = get_table(TABLE_STORES)
        response = table.get_item(Key={'id': store_id})
        return response.get('Item')
    except ClientError:
        return None


def create_store(store_data: dict) -> str:
    """Create a new store and return store ID."""
    table = get_table(TABLE_STORES)
    store_id = str(uuid.uuid4())
    store_data['id'] = store_id
    store_data['created_at'] = datetime.utcnow().isoformat()
    table.put_item(Item=store_data)
    return store_id


def query_stores_by_admin_id(admin_id: str) -> list:
    """Query stores by admin_id."""
    try:
        table = get_table(TABLE_STORES)
        response = table.query(
            IndexName='admin_id-index',
            KeyConditionExpression='admin_id = :admin_id',
            ExpressionAttributeValues={':admin_id': admin_id}
        )
        return response.get('Items', [])
    except ClientError:
        # Fallback to scan if GSI doesn't exist
        try:
            response = table.scan(
                FilterExpression='admin_id = :admin_id',
                ExpressionAttributeValues={':admin_id': admin_id}
            )
            return response.get('Items', [])
        except ClientError:
            return []


def get_product_by_id(product_id: str) -> dict | None:
    """Get product by ID."""
    try:
        table = get_table(TABLE_PRODUCTS)
        response = table.get_item(Key={'id': product_id})
        return response.get('Item')
    except ClientError:
        return None


def create_product(product_data: dict) -> str:
    """Create a new product and return product ID."""
    table = get_table(TABLE_PRODUCTS)
    product_id = str(uuid.uuid4())
    product_data['id'] = product_id
    product_data['created_at'] = datetime.utcnow().isoformat()
<<<<<<< HEAD
    # Ensure floats are converted to Decimal for DynamoDB
    table.put_item(Item=_convert_floats_to_decimal(product_data))
=======
    table.put_item(Item=product_data)
>>>>>>> 36a7adf28225fe68e4484914302ffcb424f92496
    return product_id


def scan_products() -> list:
    """Get all products."""
    try:
        table = get_table(TABLE_PRODUCTS)
        response = table.scan()
        items = response.get('Items', [])
        # Handle pagination
        while 'LastEvaluatedKey' in response:
            response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            items.extend(response.get('Items', []))
        return items
    except ClientError:
        return []


def get_inventory_by_id(inventory_id: str) -> dict | None:
    """Get inventory item by ID."""
    try:
        table = get_table(TABLE_INVENTORY)
        response = table.get_item(Key={'id': inventory_id})
        return response.get('Item')
    except ClientError:
        return None


def query_inventory_by_store(store_id: str) -> list:
    """Query inventory by store_id."""
    try:
        table = get_table(TABLE_INVENTORY)
        response = table.query(
            IndexName='store_id-index',
            KeyConditionExpression='store_id = :store_id',
            ExpressionAttributeValues={':store_id': store_id}
        )
        items = response.get('Items', [])
        # Handle pagination
        while 'LastEvaluatedKey' in response:
            response = table.query(
                IndexName='store_id-index',
                KeyConditionExpression='store_id = :store_id',
                ExpressionAttributeValues={':store_id': store_id},
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            items.extend(response.get('Items', []))
        return items
    except ClientError:
        # Fallback to scan if GSI doesn't exist
        try:
            response = table.scan(
                FilterExpression='store_id = :store_id',
                ExpressionAttributeValues={':store_id': store_id}
            )
            items = response.get('Items', [])
            # Handle pagination
            while 'LastEvaluatedKey' in response:
                response = table.scan(
                    FilterExpression='store_id = :store_id',
                    ExpressionAttributeValues={':store_id': store_id},
                    ExclusiveStartKey=response['LastEvaluatedKey']
                )
                items.extend(response.get('Items', []))
            return items
        except ClientError:
            return []


def create_inventory(inventory_data: dict) -> str:
    """Create a new inventory item and return inventory ID."""
    table = get_table(TABLE_INVENTORY)
    inventory_id = str(uuid.uuid4())
    inventory_data['id'] = inventory_id
    inventory_data['updated_at'] = datetime.utcnow().isoformat()
    table.put_item(Item=inventory_data)
    return inventory_id


def update_inventory(inventory_id: str, updates: dict) -> None:
    """Update inventory item."""
    table = get_table(TABLE_INVENTORY)
    update_expr = "SET " + ", ".join([f"{k} = :{k}" for k in updates.keys()])
    expr_values = {f":{k}": v for k, v in updates.items()}
    expr_values[':updated_at'] = datetime.utcnow().isoformat()
    update_expr += ", updated_at = :updated_at"
    
    table.update_item(
        Key={'id': inventory_id},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=expr_values
    )


def delete_inventory(inventory_id: str) -> None:
    """Delete inventory item."""
    table = get_table(TABLE_INVENTORY)
    table.delete_item(Key={'id': inventory_id})


def get_restock_request_by_id(request_id: str) -> dict | None:
    """Get restock request by ID."""
    try:
        table = get_table(TABLE_RESTOCK_REQUESTS)
        response = table.get_item(Key={'id': request_id})
        return response.get('Item')
    except ClientError:
        return None


def query_restock_requests_by_store(store_id: str) -> list:
    """Query restock requests by store_id."""
    try:
        table = get_table(TABLE_RESTOCK_REQUESTS)
        response = table.query(
            IndexName='store_id-index',
            KeyConditionExpression='store_id = :store_id',
            ExpressionAttributeValues={':store_id': store_id}
        )
        items = response.get('Items', [])
        # Handle pagination
        while 'LastEvaluatedKey' in response:
            response = table.query(
                IndexName='store_id-index',
                KeyConditionExpression='store_id = :store_id',
                ExpressionAttributeValues={':store_id': store_id},
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            items.extend(response.get('Items', []))
        return items
    except ClientError:
        # Fallback to scan if GSI doesn't exist
        try:
            response = table.scan(
                FilterExpression='store_id = :store_id',
                ExpressionAttributeValues={':store_id': store_id}
            )
            items = response.get('Items', [])
            # Handle pagination
            while 'LastEvaluatedKey' in response:
                response = table.scan(
                    FilterExpression='store_id = :store_id',
                    ExpressionAttributeValues={':store_id': store_id},
                    ExclusiveStartKey=response['LastEvaluatedKey']
                )
                items.extend(response.get('Items', []))
            return items
        except ClientError:
            return []


def scan_restock_requests(filter_status: str = None) -> list:
    """Get all restock requests, optionally filtered by status."""
    try:
        table = get_table(TABLE_RESTOCK_REQUESTS)
        if filter_status:
            response = table.scan(
                FilterExpression='#status <> :status',
                ExpressionAttributeNames={'#status': 'status'},
                ExpressionAttributeValues={':status': filter_status}
            )
        else:
            response = table.scan()
        
        items = response.get('Items', [])
        # Handle pagination
        while 'LastEvaluatedKey' in response:
            if filter_status:
                response = table.scan(
                    FilterExpression='#status <> :status',
                    ExpressionAttributeNames={'#status': 'status'},
                    ExpressionAttributeValues={':status': filter_status},
                    ExclusiveStartKey=response['LastEvaluatedKey']
                )
            else:
                response = table.scan(ExclusiveStartKey=response['LastEvaluatedKey'])
            items.extend(response.get('Items', []))
        return items
    except ClientError:
        return []


def create_restock_request(request_data: dict) -> str:
    """Create a new restock request and return request ID."""
    table = get_table(TABLE_RESTOCK_REQUESTS)
    request_id = str(uuid.uuid4())
    request_data['id'] = request_id
    now = datetime.utcnow().isoformat()
    request_data['created_at'] = now
    request_data['updated_at'] = now
    table.put_item(Item=request_data)
    return request_id


def update_restock_request(request_id: str, updates: dict) -> None:
    """Update restock request."""
    table = get_table(TABLE_RESTOCK_REQUESTS)
<<<<<<< HEAD
    # Use ExpressionAttributeNames to avoid reserved keyword issues (e.g., "status")
    expr_names = {f"#{k}": k for k in updates.keys()}
    update_expr = "SET " + ", ".join([f"#{k} = :{k}" for k in updates.keys()])
=======
    update_expr = "SET " + ", ".join([f"{k} = :{k}" for k in updates.keys()])
>>>>>>> 36a7adf28225fe68e4484914302ffcb424f92496
    expr_values = {f":{k}": v for k, v in updates.items()}
    expr_values[':updated_at'] = datetime.utcnow().isoformat()
    update_expr += ", updated_at = :updated_at"
    
    table.update_item(
        Key={'id': request_id},
        UpdateExpression=update_expr,
<<<<<<< HEAD
        ExpressionAttributeValues=expr_values,
        ExpressionAttributeNames=expr_names,
=======
        ExpressionAttributeValues=expr_values
>>>>>>> 36a7adf28225fe68e4484914302ffcb424f92496
    )


def query_users_by_role_and_admin(role: str, admin_id: str = None) -> list:
    """Query users by role and optionally admin_id."""
    try:
        table = get_table(TABLE_USERS)
        if admin_id:
            # Query by role and admin_id
            response = table.scan(
                FilterExpression='#role = :role AND admin_id = :admin_id',
                ExpressionAttributeNames={'#role': 'role'},
                ExpressionAttributeValues={':role': role, ':admin_id': admin_id}
            )
        else:
            # Query by role only
            response = table.scan(
                FilterExpression='#role = :role',
                ExpressionAttributeNames={'#role': 'role'},
                ExpressionAttributeValues={':role': role}
            )
        
        items = response.get('Items', [])
        # Handle pagination
        while 'LastEvaluatedKey' in response:
            if admin_id:
                response = table.scan(
                    FilterExpression='#role = :role AND admin_id = :admin_id',
                    ExpressionAttributeNames={'#role': 'role'},
                    ExpressionAttributeValues={':role': role, ':admin_id': admin_id},
                    ExclusiveStartKey=response['LastEvaluatedKey']
                )
            else:
                response = table.scan(
                    FilterExpression='#role = :role',
                    ExpressionAttributeNames={'#role': 'role'},
                    ExpressionAttributeValues={':role': role},
                    ExclusiveStartKey=response['LastEvaluatedKey']
                )
            items.extend(response.get('Items', []))
        return items
    except ClientError:
        return []


def query_user_by_store_id(store_id: str, role: str = 'store_manager') -> dict | None:
    """Query user by store_id and role."""
    try:
        table = get_table(TABLE_USERS)
        response = table.scan(
            FilterExpression='store_id = :store_id AND #role = :role',
            ExpressionAttributeNames={'#role': 'role'},
            ExpressionAttributeValues={':store_id': store_id, ':role': role}
        )
        items = response.get('Items', [])
        return items[0] if items else None
    except ClientError:
        return None


def query_admin_by_admin_id(admin_id: str) -> dict | None:
    """Query admin user by admin_id."""
    try:
        table = get_table(TABLE_USERS)
        response = table.scan(
            FilterExpression='admin_id = :admin_id AND #role = :role',
            ExpressionAttributeNames={'#role': 'role'},
            ExpressionAttributeValues={':admin_id': admin_id, ':role': 'admin'}
        )
        items = response.get('Items', [])
        return items[0] if items else None
    except ClientError:
        return None


def get_first_store() -> dict | None:
    """Get first store (for auto-assignment)."""
    try:
        table = get_table(TABLE_STORES)
        response = table.scan(Limit=1)
        items = response.get('Items', [])
        return items[0] if items else None
    except ClientError:
        return None


# -----------------------
# AUTHENTICATION HELPERS
# -----------------------
def current_user() -> dict | None:
    """Get current user from session."""
    uid = session.get("user_id")
    if not uid:
        return None
    return get_user_by_id(uid)


def login_required(view):
    """Decorator to require login."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapper


def role_required(*roles: str):
    """Decorator to require specific role(s)."""
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
    """Inject user into template context."""
    return {"me": current_user(), "role": session.get("role")}


# -----------------------
# ROUTES
# -----------------------
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

    user = get_user_by_email(email)
    if not user:
        return jsonify({"ok": False, "error": "Invalid email or password"}), 401

    # Check password
    if not check_password_hash(user.get('password_hash', ''), password):
        return jsonify({"ok": False, "error": "Invalid email or password"}), 401

    # Check if user's role matches the selected role
    if selected_role and user.get('role') != selected_role:
        # Clear selected role from session
        session.pop("selected_role", None)
        role_names = {
            "admin": "Admin",
            "store_manager": "Store Manager",
            "supplier": "Supplier"
        }
        selected_name = role_names.get(selected_role, selected_role)
        user_role_name = role_names.get(user.get('role'), user.get('role'))
        return jsonify({
            "ok": False,
            "error": f"Access denied. You are logged in as {user_role_name}, but you selected {selected_name} role. Please select the correct role from the home page."
        }), 403

    # Clear selected role from session after successful validation
    session.pop("selected_role", None)

    # Auto-assign store_manager to first store if missing
    if user.get('role') == "store_manager" and not user.get('store_id'):
        first_store = get_first_store()
        if not first_store:
            # Create default store
            store_data = {
                'name': 'Default Store',
                'location': 'Main Location',
                'admin_id': user.get('admin_id', 'DEFAULT')
            }
            store_id = create_store(store_data)
            first_store = get_store_by_id(store_id)
        update_user(user['id'], {'store_id': first_store['id']})
        user['store_id'] = first_store['id']

    session["user_id"] = user['id']
    session["role"] = user.get('role')
    session["store_id"] = user.get('store_id')
    session["admin_id"] = user.get('admin_id')  # Store admin_id in session for filtering

    # Send login notification
    send_notification(
        "User Login",
        f"User {user.get('name')} ({user.get('email')}) with role {user.get('role')} logged in."
    )

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
    existing = get_user_by_email(email)
    if existing:
        return jsonify({"ok": False, "error": "Email already registered"}), 409

    # Create new user
    try:
        if role == "admin":
            # Admin signup - generates Admin ID automatically
            # Generate unique Admin ID (Brand ID)
            admin_id = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
            # Ensure uniqueness
            while query_admin_by_admin_id(admin_id):
                admin_id = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
            
            password_hash = generate_password_hash(password)
            user_data = {
                'name': name,
                'email': email,
                'password_hash': password_hash,
                'role': role,
                'admin_id': admin_id,
                'brand_id': admin_id,
                'store_id': None
            }
            user_id = create_user(user_data)
            
            # Send admin signup notification
            send_notification(
                "Admin Signup",
                f"New admin user registered: {name} ({email}) with Admin ID: {admin_id}"
            )
            
            return jsonify({"ok": True, "redirect": url_for("login"), "admin_id": admin_id})
        
        elif role == "store_manager":
            # Store Manager signup - requires Admin ID, Store Name, Store Location
            admin_id = (data.get("admin_id") or "").strip().upper()
            store_name = (data.get("store_name") or "").strip()
            store_location = (data.get("store_location") or "").strip()
            
            if not admin_id or not store_name:
                return jsonify({"ok": False, "error": "Admin ID and Store Name are required"}), 400
            
            # Verify Admin ID exists
            admin_user = query_admin_by_admin_id(admin_id)
            if not admin_user:
                return jsonify({"ok": False, "error": "Invalid Admin ID. Please check and try again."}), 400
            
            # Create store
            store_data = {
                'name': store_name,
                'location': store_location,
                'admin_id': admin_id
            }
            store_id = create_store(store_data)
            
            # Create store manager linked to admin_id and store
            password_hash = generate_password_hash(password)
            user_data = {
                'name': name,
                'email': email,
                'password_hash': password_hash,
                'role': role,
                'admin_id': admin_id,
                'store_id': store_id
            }
            user_id = create_user(user_data)
            
            # Send store manager signup notification
            send_notification(
                "Store Manager Signup",
                f"New store manager registered: {name} ({email}) for store: {store_name} under Admin ID: {admin_id}"
            )
            
            return jsonify({"ok": True, "redirect": url_for("login"), "store_id": store_id})
        
        else:
            # Supplier signup - no extra fields
            password_hash = generate_password_hash(password)
            user_data = {
                'name': name,
                'email': email,
                'password_hash': password_hash,
                'role': role,
                'store_id': None,
                'admin_id': None
            }
            user_id = create_user(user_data)
            
            # Send supplier signup notification
            send_notification(
                "Supplier Signup",
                f"New supplier registered: {name} ({email})"
            )
        
        # Send general user signup notification
        send_notification(
            "User Signup",
            f"New user registered: {name} ({email}) with role: {role}"
        )
        
        return jsonify({"ok": True, "redirect": url_for("login")})
    except Exception as e:
        # Log the actual error for debugging
        import traceback
        error_msg = str(e)
        print(f"Signup error: {error_msg}")
        print(traceback.format_exc())
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
        if user and user.get('role') == "admin":
            admin_id = user.get('admin_id')
            session["admin_id"] = admin_id
        else:
            return jsonify({"ok": False, "error": "Admin ID not found"}), 400
    
    # Filter all queries by admin_id
    stores = query_stores_by_admin_id(admin_id)
    stores_count = len(stores)
    
    store_managers = query_users_by_role_and_admin("store_manager", admin_id)
    users_count = len(store_managers) + 1  # Store managers + 1 admin
    
    # Count products in inventory of stores under this admin
    store_ids = [s['id'] for s in stores]
    products_count = 0
    product_ids_set = set()
    for store_id in store_ids:
        inventory_items = query_inventory_by_store(store_id)
        for inv in inventory_items:
            if inv.get('product_id') and inv['product_id'] not in product_ids_set:
                product_ids_set.add(inv['product_id'])
                products_count += 1
    
    # Count restock requests for stores under this admin
    requests_count = 0
    all_requests = scan_restock_requests()
    for req in all_requests:
        if req.get('store_id') in store_ids:
            requests_count += 1
    
    # Get stores under this admin with managers
    stores_list = []
    for store in stores:
        manager = query_user_by_store_id(store['id'], 'store_manager')
        stores_list.append({
            "id": store['id'],
            "name": store.get('name', ''),
            "location": store.get('location', ''),
            "manager": manager.get('name') if manager else "Unassigned",
        })
    
    # Get recent requests (limit 10)
    recent_requests = []
    for req in sorted(all_requests, key=lambda x: x.get('created_at', ''), reverse=True):
        if req.get('store_id') in store_ids:
            store = get_store_by_id(req['store_id'])
            product = get_product_by_id(req.get('product_id', ''))
            supplier = None
            if req.get('supplier_id'):
                supplier = get_user_by_id(req['supplier_id'])
            
            recent_requests.append({
                "id": req['id'],
                "store_id": store['id'] if store else '',
                "store": store.get('name', '') if store else '',
                "store_location": store.get('location', '') if store else '',
                "product": product.get('name', '') if product else '',
                "requested_qty": req.get('requested_qty', 0),
                "status": req.get('status', 'pending'),
                "supplier": supplier.get('name') if supplier else "Unassigned",
                "created_at": req.get('created_at', ''),
            })
            if len(recent_requests) >= 10:
                break

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
            "recent_requests": recent_requests,
        }
    )


def get_store_manager_store_id():
    """Get store_id for store_manager, auto-assign if missing."""
    store_id = session.get("store_id")
    if store_id:
        return store_id
    
    # Check user object from database
    user = current_user()
    if user and user.get('role') == "store_manager":
        if user.get('store_id'):
            # Update session
            session["store_id"] = user['store_id']
            return user['store_id']
        else:
            # Auto-assign to first store
            first_store = get_first_store()
            if not first_store:
                # Create default store
                store_data = {
                    'name': 'Default Store',
                    'location': 'Main Location',
                    'admin_id': user.get('admin_id', 'DEFAULT')
                }
                store_id = create_store(store_data)
                first_store = get_store_by_id(store_id)
            update_user(user['id'], {'store_id': first_store['id']})
            session["store_id"] = first_store['id']
            return first_store['id']
    
    return None


@app.get("/api/store/inventory")
@role_required("store_manager")
def api_store_inventory_list():
    store_id = get_store_manager_store_id()
    if not store_id:
        return jsonify({"ok": False, "error": "Store not assigned"}), 400

    # Ensure store manager can only access their own store
    user = current_user()
    if user.get('store_id') != store_id:
        return jsonify({"ok": False, "error": "Unauthorized access"}), 403

    inventory_items = query_inventory_by_store(store_id)
    items = []
    for inv in inventory_items:
        product = get_product_by_id(inv.get('product_id', ''))
        if product:
            items.append({
                "inventory_id": inv['id'],
                "product_id": product['id'],
                "product_name": product.get('name', ''),
                "category": product.get('category', ''),
                "price": float(product.get('price', 0)),
                "quantity": int(inv.get('quantity', 0)),
                "updated_at": inv.get('updated_at', ''),
            })
    
    # Sort by product name
    items.sort(key=lambda x: x['product_name'])

    return jsonify({"ok": True, "items": items})


@app.post("/api/store/inventory/update")
@role_required("store_manager")
def api_store_inventory_update():
    store_id = get_store_manager_store_id()
    if not store_id:
        return jsonify({"ok": False, "error": "Store not assigned"}), 400

    # Ensure store manager can only access their own store
    user = current_user()
    if user.get('store_id') != store_id:
        return jsonify({"ok": False, "error": "Unauthorized access"}), 403

    data = request.get_json(force=True)
    inventory_id = data.get("inventory_id")
    quantity = int(data.get("quantity", 0))

    inv = get_inventory_by_id(inventory_id)
    if not inv:
        return jsonify({"ok": False, "error": "Inventory item not found"}), 404

    if inv.get('store_id') != store_id:
        return jsonify({"ok": False, "error": "Unauthorized access"}), 403

    update_inventory(inventory_id, {'quantity': max(0, quantity)})
    
    # Send inventory update notification
    product = get_product_by_id(inv.get('product_id', ''))
    send_notification(
        "Inventory Update",
        f"Inventory updated for product {product.get('name', 'Unknown')} in store {store_id}. New quantity: {max(0, quantity)}"
    )
    
    return jsonify({"ok": True})


@app.post("/api/store/inventory/remove")
@role_required("store_manager")
def api_store_inventory_remove():
    store_id = get_store_manager_store_id()
    if not store_id:
        return jsonify({"ok": False, "error": "Store not assigned"}), 400

    # Ensure store manager can only access their own store
    user = current_user()
    if user.get('store_id') != store_id:
        return jsonify({"ok": False, "error": "Unauthorized access"}), 403

    data = request.get_json(force=True)
    inventory_id = data.get("inventory_id")
    remove_completely = data.get("remove_completely", False)

    inv = get_inventory_by_id(inventory_id)
    if not inv:
        return jsonify({"ok": False, "error": "Inventory item not found"}), 404

    if inv.get('store_id') != store_id:
        return jsonify({"ok": False, "error": "Unauthorized access"}), 403

    if remove_completely:
        delete_inventory(inventory_id)
    else:
        # Just set quantity to 0
        update_inventory(inventory_id, {'quantity': 0})
    
    return jsonify({"ok": True})


@app.get("/api/store/products")
@role_required("store_manager")
def api_store_products():
    products = scan_products()
    products_list = [
        {
            "id": p['id'],
            "name": p.get('name', ''),
            "category": p.get('category', ''),
            "price": float(p.get('price', 0))
        }
        for p in products
    ]
    # Sort by name
    products_list.sort(key=lambda x: x['name'])
    return jsonify({"ok": True, "products": products_list})


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
        product_data = {
            'name': name,
            'category': category,
            'price': price,
            'supplier_id': None
        }
        product_id = create_product(product_data)

        # Add to inventory
        inventory_data = {
            'store_id': store_id,
            'product_id': product_id,
            'quantity': quantity
        }
        create_inventory(inventory_data)
        
        # Send product creation notification
        send_notification(
            "Product Creation",
            f"New product created: {name} (Category: {category}, Price: ${price:.2f}) in store {store_id} with initial quantity: {quantity}"
        )

        return jsonify({"ok": True, "id": product_id})
    except Exception as e:
        import traceback
        print(f"Product creation error: {e}")
        print(traceback.format_exc())
        return jsonify({"ok": False, "error": "Failed to add product. Please try again."}), 500


@app.post("/api/store/restock/create")
@role_required("store_manager")
def api_store_restock_create():
    store_id = get_store_manager_store_id()
    if not store_id:
        return jsonify({"ok": False, "error": "Store not assigned"}), 400

    # Ensure store manager can only create requests for their own store
    user = current_user()
    if user.get('store_id') != store_id:
        return jsonify({"ok": False, "error": "Unauthorized access"}), 403

    data = request.get_json(force=True)
    product_id = data.get("product_id")
    requested_qty = max(1, int(data.get("requested_qty", 1)))

    product = get_product_by_id(product_id)
    if not product:
        return jsonify({"ok": False, "error": "Product not found"}), 404

    # Get store details for request
    store = get_store_by_id(store_id)
    if not store:
        return jsonify({"ok": False, "error": "Store not found"}), 404

    # Use product's supplier_id, but allow None (unassigned requests can be seen by all suppliers)
    supplier_id = product.get('supplier_id') if product.get('supplier_id') else None

    request_data = {
        'store_id': store_id,
        'product_id': product_id,
        'supplier_id': supplier_id,
        'requested_qty': requested_qty,
        'status': 'pending'
    }
    request_id = create_restock_request(request_data)
    
    # Send restock request creation notification
    send_notification(
        "Restock Request Created",
        f"New restock request created: {requested_qty} units of {product.get('name', 'Unknown')} for store {store.get('name', 'Unknown')} (ID: {request_id})"
    )
    
    return jsonify({
        "ok": True, 
        "id": request_id,
        "store_id": store['id'],
        "store_name": store.get('name', ''),
        "store_location": store.get('location', ''),
    })


@app.get("/api/store/requests")
@role_required("store_manager")
def api_store_requests():
    store_id = get_store_manager_store_id()
    if not store_id:
        return jsonify({"ok": False, "error": "Store not assigned"}), 400

    # Ensure store manager can only access their own store requests
    user = current_user()
    if user.get('store_id') != store_id:
        return jsonify({"ok": False, "error": "Unauthorized access"}), 403

    # Get all requests for this store
    requests = query_restock_requests_by_store(store_id)
    
    items = []
    for req in requests:
        product = get_product_by_id(req.get('product_id', ''))
        supplier = None
        if req.get('supplier_id'):
            supplier = get_user_by_id(req['supplier_id'])
        
        items.append({
            "id": req['id'],
            "product_id": product['id'] if product else '',
            "product_name": product.get('name', '') if product else '',
            "requested_qty": req.get('requested_qty', 0),
            "status": req.get('status', 'pending'),
            "supplier": supplier.get('name') if supplier else "Unassigned",
            "created_at": req.get('created_at', ''),
            "updated_at": req.get('updated_at', ''),
        })
    
    # Sort by created_at descending
    items.sort(key=lambda x: x['created_at'], reverse=True)
    
    return jsonify({"ok": True, "items": items})


@app.get("/api/supplier/requests")
@role_required("supplier")
def api_supplier_requests():
    supplier_id = session.get("user_id")
    # Show ALL requests so suppliers can see and decide which ones to accept
    # Suppliers can accept any request, which will assign it to them
    all_requests = scan_restock_requests(filter_status='rejected')  # Don't show rejected requests
    
    items = []
    for req in all_requests:
        store = get_store_by_id(req.get('store_id', ''))
        product = get_product_by_id(req.get('product_id', ''))
        
        items.append({
            "id": req['id'],
            "store_id": store['id'] if store else '',
            "store": store.get('name', '') if store else '',
            "store_location": store.get('location', '') if store else '',
            "product": product.get('name', '') if product else '',
            "requested_qty": req.get('requested_qty', 0),
            "status": req.get('status', 'pending'),
            "created_at": req.get('created_at', ''),
        })
    
    # Sort by created_at descending
    items.sort(key=lambda x: x['created_at'], reverse=True)
    
    return jsonify({"ok": True, "items": items})


@app.post("/api/supplier/requests/update")
@role_required("supplier")
def api_supplier_requests_update():
    supplier_id = session.get("user_id")
    data = request.get_json(force=True)
    request_id = data.get("id")
    status = (data.get("status") or "").strip().lower()

    if status not in {"accepted", "rejected", "shipped"}:
        return jsonify({"ok": False, "error": "Invalid status"}), 400

<<<<<<< HEAD
    try:
        # Suppliers can accept/update any pending request (except rejected ones)
        # When accepting a request, assign it to this supplier
        req = get_restock_request_by_id(request_id)
        
        if not req:
            return jsonify({"ok": False, "error": "Request not found"}), 404

        # If accepting a request (accepted or shipped), assign it to this supplier
        # This allows suppliers to "claim" requests by accepting them
        updates = {'status': status}
        if status in {"accepted", "shipped"}:
            updates['supplier_id'] = supplier_id
        
        update_restock_request(request_id, updates)
        
        # Send restock request status update notification (defensive against missing data)
        product = get_product_by_id(req.get('product_id', ''))
        store = get_store_by_id(req.get('store_id', ''))
        supplier = get_user_by_id(supplier_id)

        product_name = product.get('name', 'Unknown') if product else 'Unknown'
        store_name = store.get('name', 'Unknown') if store else 'Unknown'
        supplier_name = supplier.get('name', 'Unknown') if supplier else 'Unknown'

        send_notification(
            "Restock Request Status Update",
            f"Restock request {request_id} status updated to {status} by supplier {supplier_name} for product {product_name} at store {store_name}"
        )
    except Exception as e:
        # Make sure any unexpected backend issue returns a clean JSON error
        import traceback
        print("Error updating supplier request:", e)
        print(traceback.format_exc())
        return jsonify({"ok": False, "error": "Failed to update request. Please try again."}), 500
=======
    # Suppliers can accept/update any pending request (except rejected ones)
    # When accepting a request, assign it to this supplier
    req = get_restock_request_by_id(request_id)
    
    if not req:
        return jsonify({"ok": False, "error": "Request not found"}), 404

    # If accepting a request (accepted or shipped), assign it to this supplier
    # This allows suppliers to "claim" requests by accepting them
    updates = {'status': status}
    if status in {"accepted", "shipped"}:
        updates['supplier_id'] = supplier_id
    
    update_restock_request(request_id, updates)
    
    # Send restock request status update notification
    product = get_product_by_id(req.get('product_id', ''))
    store = get_store_by_id(req.get('store_id', ''))
    supplier = get_user_by_id(supplier_id)
    send_notification(
        "Restock Request Status Update",
        f"Restock request {request_id} status updated to {status} by supplier {supplier.get('name', 'Unknown')} for product {product.get('name', 'Unknown')} at store {store.get('name', 'Unknown')}"
    )
>>>>>>> 36a7adf28225fe68e4484914302ffcb424f92496
    
    return jsonify({"ok": True})


# -----------------------
# CLI helpers
# -----------------------


def parse_args():
    parser = argparse.ArgumentParser(description="StyleLane AWS app")
    parser.add_argument("--seed", action="store_true", help="Seed demo data")
    return parser.parse_args()


def seed_db() -> None:
    """Seed demo data."""
    with app.app_context():
        # Check if users already exist
        existing_users = scan_products()  # Quick check - if products exist, likely seeded
        if existing_users:
            print("Database already has data. Skipping seed.")
            return

        # Generate Admin ID
        admin_id = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))

        # Create admin
        admin_data = {
            'name': 'Admin',
            'email': 'admin@stylelane.local',
            'password_hash': generate_password_hash('admin123'),
            'role': 'admin',
            'store_id': None,
            'admin_id': admin_id,
            'brand_id': admin_id
        }
        admin_id_db = create_user(admin_data)

        # Create main store
        store_data = {
            'name': 'StyleLane - Main Store',
            'location': 'City Center',
            'admin_id': admin_id
        }
        main_store_id = create_store(store_data)

        # Create supplier
        supplier_data = {
            'name': 'Supplier',
            'email': 'supplier@stylelane.local',
            'password_hash': generate_password_hash('supplier123'),
            'role': 'supplier',
            'store_id': None,
            'admin_id': None
        }
        supplier_id = create_user(supplier_data)

        # Create manager
        manager_data = {
            'name': 'Store Manager',
            'email': 'manager@stylelane.local',
            'password_hash': generate_password_hash('manager123'),
            'role': 'store_manager',
            'store_id': main_store_id,
            'admin_id': admin_id
        }
        manager_id = create_user(manager_data)

        # Create products
        p1_data = {
            'name': 'Classic Denim Jacket',
            'category': 'Outerwear',
            'price': 79.99,
            'supplier_id': supplier_id
        }
        p1_id = create_product(p1_data)

        p2_data = {
            'name': 'Cotton T-Shirt',
            'category': 'Basics',
            'price': 19.99,
            'supplier_id': supplier_id
        }
        p2_id = create_product(p2_data)

        p3_data = {
            'name': 'Slim Fit Chinos',
            'category': 'Bottoms',
            'price': 49.99,
            'supplier_id': supplier_id
        }
        p3_id = create_product(p3_data)

        # Create inventory
        inv1_data = {
            'store_id': main_store_id,
            'product_id': p1_id,
            'quantity': 12
        }
        create_inventory(inv1_data)

        inv2_data = {
            'store_id': main_store_id,
            'product_id': p2_id,
            'quantity': 35
        }
        create_inventory(inv2_data)

        inv3_data = {
            'store_id': main_store_id,
            'product_id': p3_id,
            'quantity': 8
        }
        create_inventory(inv3_data)

        print(f"Demo Admin ID (Brand ID): {admin_id}")


if __name__ == "__main__":
    args = parse_args()
    if args.seed:
        seed_db()
        print("DB seeded.")
    else:
        app.run(debug=True)

