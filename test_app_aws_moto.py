import importlib

import boto3
import pytest
from moto import mock_aws


@pytest.fixture(scope="function")
def app_module():
    """
    Load the Flask app inside a moto AWS mock so that all boto3 calls
    (DynamoDB + SNS) are intercepted and no real AWS resources are used.
    """
    with mock_aws():
        # Import here so that app_aws' global boto3.resource/client are created
        # against the moto backend, not real AWS.
        import app_aws

        importlib.reload(app_aws)

        # Recreate AWS resources using the (mocked) region from the module
        dynamodb = boto3.client("dynamodb", region_name=app_aws.REGION)
        sns = boto3.client("sns", region_name=app_aws.REGION)

        # Create SNS topic that matches the ARN configured in the app
        # (moto will generate the same ARN pattern for this topic name).
        sns.create_topic(Name="stylelane-notifications")

        # Helper: create all DynamoDB tables that the app expects
        def create_tables():
            # Users table with GSI for email
            dynamodb.create_table(
                TableName=app_aws.TABLE_USERS,
                KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
                AttributeDefinitions=[
                    {"AttributeName": "id", "AttributeType": "S"},
                    {"AttributeName": "email", "AttributeType": "S"},
                ],
                GlobalSecondaryIndexes=[
                    {
                        "IndexName": "email-index",
                        "KeySchema": [
                            {
                                "AttributeName": "email",
                                "KeyType": "HASH",
                            }
                        ],
                        "Projection": {"ProjectionType": "ALL"},
                        "ProvisionedThroughput": {
                            "ReadCapacityUnits": 5,
                            "WriteCapacityUnits": 5,
                        },
                    }
                ],
                BillingMode="PAY_PER_REQUEST",
            )

            # Stores table with GSI for admin_id
            dynamodb.create_table(
                TableName=app_aws.TABLE_STORES,
                KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
                AttributeDefinitions=[
                    {"AttributeName": "id", "AttributeType": "S"},
                    {"AttributeName": "admin_id", "AttributeType": "S"},
                ],
                GlobalSecondaryIndexes=[
                    {
                        "IndexName": "admin_id-index",
                        "KeySchema": [
                            {
                                "AttributeName": "admin_id",
                                "KeyType": "HASH",
                            }
                        ],
                        "Projection": {"ProjectionType": "ALL"},
                        "ProvisionedThroughput": {
                            "ReadCapacityUnits": 5,
                            "WriteCapacityUnits": 5,
                        },
                    }
                ],
                BillingMode="PAY_PER_REQUEST",
            )

            # Products table
            dynamodb.create_table(
                TableName=app_aws.TABLE_PRODUCTS,
                KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
                AttributeDefinitions=[
                    {"AttributeName": "id", "AttributeType": "S"},
                ],
                BillingMode="PAY_PER_REQUEST",
            )

            # Inventory table with GSI for store_id
            dynamodb.create_table(
                TableName=app_aws.TABLE_INVENTORY,
                KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
                AttributeDefinitions=[
                    {"AttributeName": "id", "AttributeType": "S"},
                    {"AttributeName": "store_id", "AttributeType": "S"},
                ],
                GlobalSecondaryIndexes=[
                    {
                        "IndexName": "store_id-index",
                        "KeySchema": [
                            {
                                "AttributeName": "store_id",
                                "KeyType": "HASH",
                            }
                        ],
                        "Projection": {"ProjectionType": "ALL"},
                        "ProvisionedThroughput": {
                            "ReadCapacityUnits": 5,
                            "WriteCapacityUnits": 5,
                        },
                    }
                ],
                BillingMode="PAY_PER_REQUEST",
            )

            # Restock requests table with GSI for store_id
            dynamodb.create_table(
                TableName=app_aws.TABLE_RESTOCK_REQUESTS,
                KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
                AttributeDefinitions=[
                    {"AttributeName": "id", "AttributeType": "S"},
                    {"AttributeName": "store_id", "AttributeType": "S"},
                ],
                GlobalSecondaryIndexes=[
                    {
                        "IndexName": "store_id-index",
                        "KeySchema": [
                            {
                                "AttributeName": "store_id",
                                "KeyType": "HASH",
                            }
                        ],
                        "Projection": {"ProjectionType": "ALL"},
                        "ProvisionedThroughput": {
                            "ReadCapacityUnits": 5,
                            "WriteCapacityUnits": 5,
                        },
                    }
                ],
                BillingMode="PAY_PER_REQUEST",
            )

        create_tables()

        yield app_aws


@pytest.fixture()
def client(app_module):
    """Flask test client bound to the moto-backed AWS resources."""
    app = app_module.app
    with app.test_client() as c:
        with app.app_context():
            yield c


def test_seed_db_does_not_raise(app_module):
    """
    Run the seed_db helper inside the moto environment.
    This will exercise a lot of the DynamoDB helper code and catch
    expression / schema issues that would only appear at runtime.
    """
    app_module.seed_db()  # Should complete without throwing


def test_index_page_renders(client):
    """Basic smoke-test: GET / should return HTTP 200."""
    resp = client.get("/")
    assert resp.status_code == 200


