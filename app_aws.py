from __future__ import annotations

import argparse
import secrets
import string
import uuid
from datetime import datetime
from functools import wraps
from decimal import Decimal

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

TABLE_USERS = 'stylelane_users'
TABLE_STORES = 'stylelane_stores'
TABLE_PRODUCTS = 'stylelane_products'
TABLE_INVENTORY = 'stylelane_inventory'
TABLE_RESTOCK_REQUESTS = 'stylelane_restock_requests'

SNS_TOPIC_ARN = 'arn:aws:sns:us-east-1:194722438347:stylelane_topic'

dynamodb = boto3.resource('dynamodb', region_name=REGION)
sns = boto3.client('sns', region_name=REGION)

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev-only-change-me"


# -----------------------
# HOME ROUTE (ADDED)
# -----------------------
@app.route("/")
def home():
    return render_template("index.html")


# -----------------------
# SNS NOTIFICATION HELPER
# -----------------------
def send_notification(subject: str, message: str) -> None:
    try:
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=subject,
            Message=message
        )
    except ClientError as e:
        print(f"SNS notification error: {e}")


# -----------------------
# DYNAMODB HELPERS
# -----------------------
def get_table(table_name: str):
    return dynamodb.Table(table_name)


def _convert_floats_to_decimal(data):
    if isinstance(data, float):
        return Decimal(str(data))
    if isinstance(data, dict):
        return {k: _convert_floats_to_decimal(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_convert_floats_to_decimal(v) for v in data]
    return data


def get_user_by_id(user_id: str):
    try:
        table = get_table(TABLE_USERS)
        return table.get_item(Key={'id': user_id}).get('Item')
    except ClientError:
        return None


def get_user_by_email(email: str):
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
        return None


def create_user(user_data: dict) -> str:
    table = get_table(TABLE_USERS)
    user_id = str(uuid.uuid4())
    user_data['id'] = user_id
    user_data['created_at'] = datetime.utcnow().isoformat()
    table.put_item(Item=user_data)
    return user_id


def get_store_by_id(store_id: str):
    try:
        return get_table(TABLE_STORES).get_item(Key={'id': store_id}).get('Item')
    except ClientError:
        return None


def create_store(store_data: dict) -> str:
    table = get_table(TABLE_STORES)
    store_id = str(uuid.uuid4())
    store_data['id'] = store_id
    store_data['created_at'] = datetime.utcnow().isoformat()
    table.put_item(Item=store_data)
    return store_id


def get_product_by_id(product_id: str):
    try:
        return get_table(TABLE_PRODUCTS).get_item(Key={'id': product_id}).get('Item')
    except ClientError:
        return None


def create_product(product_data: dict) -> str:
    table = get_table(TABLE_PRODUCTS)
    product_id = str(uuid.uuid4())
    product_data['id'] = product_id
    product_data['created_at'] = datetime.utcnow().isoformat()
    table.put_item(Item=_convert_floats_to_decimal(product_data))
    return product_id


def create_inventory(inventory_data: dict) -> str:
    table = get_table(TABLE_INVENTORY)
    inventory_id = str(uuid.uuid4())
    inventory_data['id'] = inventory_id
    inventory_data['updated_at'] = datetime.utcnow().isoformat()
    table.put_item(Item=inventory_data)
    return inventory_id


def get_restock_request_by_id(request_id: str):
    try:
        return get_table(TABLE_RESTOCK_REQUESTS).get_item(Key={'id': request_id}).get('Item')
    except ClientError:
        return None


def update_restock_request(request_id: str, updates: dict) -> None:
    table = get_table(TABLE_RESTOCK_REQUESTS)
    expr_names = {f"#{k}": k for k in updates.keys()}
    update_expr = "SET " + ", ".join([f"#{k} = :{k}" for k in updates.keys()])
    expr_values = {f":{k}": v for k, v in updates.items()}
    expr_values[':updated_at'] = datetime.utcnow().isoformat()
    update_expr += ", updated_at = :updated_at"

    table.update_item(
        Key={'id': request_id},
        UpdateExpression=update_expr,
        ExpressionAttributeNames=expr_names,
        ExpressionAttributeValues=expr_values
    )


# -----------------------
# AUTH HELPERS
# -----------------------
def current_user():
    uid = session.get("user_id")
    return get_user_by_id(uid) if uid else None


def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            if session.get("role") not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator


# -----------------------
# SUPPLIER UPDATE API
# -----------------------
@app.post("/api/supplier/requests/update")
@role_required("supplier")
def api_supplier_requests_update():
    supplier_id = session.get("user_id")
    data = request.get_json(force=True)
    request_id = data.get("id")
    status = (data.get("status") or "").strip().lower()

    if status not in {"accepted", "rejected", "shipped"}:
        return jsonify({"ok": False, "error": "Invalid status"}), 400

    try:
        req = get_restock_request_by_id(request_id)
        if not req:
            return jsonify({"ok": False, "error": "Request not found"}), 404

        updates = {'status': status}
        if status in {"accepted", "shipped"}:
            updates['supplier_id'] = supplier_id

        update_restock_request(request_id, updates)

        send_notification(
            "Restock Request Status Update",
            f"Restock request {request_id} updated to {status}"
        )
    except Exception:
        import traceback
        print(traceback.format_exc())
        return jsonify({"ok": False, "error": "Failed to update request"}), 500

    return jsonify({"ok": True})


# -----------------------
# MAIN
# -----------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
