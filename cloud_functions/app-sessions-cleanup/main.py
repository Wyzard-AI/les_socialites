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

# Function to delete sessions where user_id IS NULL, empty, or _fresh is false
def main(request: Request):
    connection = get_connection()
    cursor = connection.cursor()

    try:
        # Delete old conversations
        cursor.execute("""
            WITH sessions_to_delete AS (
                SELECT
                    DISTINCT session_id
                FROM
                    app.sessions
                WHERE
                    (data::jsonb->'_fresh' = 'false') OR (updated_at < (current_timestamp - interval '720 minutes'))
            )
            
            DELETE FROM app.conversations
            WHERE session_id IN (SELECT session_id FROM sessions_to_delete);
        """)
        
        # Delete old sessions
        cursor.execute("""
            DELETE FROM app.sessions
            WHERE (data::jsonb->'_fresh' = 'false')
            OR (updated_at < (current_timestamp - interval '720 minutes'));
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
