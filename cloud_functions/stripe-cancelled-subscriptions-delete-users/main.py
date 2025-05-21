import json
from google.cloud.sql.connector import Connector, IPTypes
from google.cloud import secretmanager
from flask import Request
from datetime import datetime, timedelta, timezone

# Function to get secrets
def get_secret(secret_name):
    secret_client = secretmanager.SecretManagerServiceClient()
    secret_resource_name = f"projects/916481347801/secrets/{secret_name}/versions/1"
    response = secret_client.access_secret_version(name=secret_resource_name)
    secret_payload = response.payload.data.decode('UTF-8')
    return secret_payload

# Function to establish a connection to CloudSQL
def get_connection():
    connector = Connector()
    connection = connector.connect(
        "les-socialites-chat-gpt:us-east1:wyzard",  # Replace with your actual instance connection name
        "pg8000",  # PostgreSQL driver
        user="postgres",
        password=get_secret('cloudsql-postgres-user-password'),
        db="wyzard_flask",
        ip_type=IPTypes.PUBLIC
    )
    return connection

# Function to delete users with cancelled subscriptions that are no longer valid
def main(request: Request):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        cursor.execute("""
            WITH sessions_to_delete AS (
                SELECT
                    DISTINCT email
                FROM
                    app.stripe_users
                WHERE
                    is_cancelled = TRUE
                    AND valid_until < CURRENT_TIMESTAMP()
            )
            
            DELETE FROM app.users
            WHERE email IN (SELECT email FROM users_to_delete);
        """)

        connection.commit()
        return "Cleanup completed successfully."

    except Exception as e:
        return "Error during cleanup"

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()
