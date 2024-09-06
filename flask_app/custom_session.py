import json
from flask.sessions import SessionInterface, SessionMixin
from uuid import UUID, uuid4
from datetime import datetime, timedelta, timezone
from werkzeug.datastructures import CallbackDict
from google.cloud import secretmanager
from google.cloud.sql.connector import Connector, IPTypes

# CloudSQL Connection
connector = Connector()

def get_secret(secret_name):
    secret_client = secretmanager.SecretManagerServiceClient()
    secret_resource_name = f"projects/916481347801/secrets/{secret_name}/versions/1"
    response = secret_client.access_secret_version(name=secret_resource_name)
    secret_payload = response.payload.data.decode('UTF-8')
    return secret_payload

def get_connection():
    return connector.connect(
        "les-socialites-chat-gpt:us-east1:wyzard",  # Replace with your actual instance connection name
        "pg8000",  # This is the PostgreSQL driver for Cloud SQL
        user="postgres",
        password=get_secret('cloudsql-postgres-user-password'),  # Securely store and retrieve from environment variables
        db="wyzard_flask",
        ip_type=IPTypes.PUBLIC,  # or IPTypes.PRIVATE for private IP
    )

class DateTimeUUIDEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, UUID):
            return str(obj)
        return super(DateTimeUUIDEncoder, self).default(obj)

class CloudSQLSession(CallbackDict, SessionMixin):
    def __init__(self, initial=None, sid=None, new=False):
        super().__init__(initial)
        self.sid = sid
        self.new = new
        self.modified = False

class CloudSQLSessionInterface(SessionInterface):
    session_class = CloudSQLSession

    def open_session(self, app, request):
        session_cookie_name = app.config.get('SESSION_COOKIE_NAME', 'session')
        sid = request.cookies.get(session_cookie_name)
        if not sid:
            sid = str(uuid4())
            return self.session_class(sid=sid, new=True)

        connection = get_connection()
        cursor = connection.cursor()
        try:
            cursor.execute("SELECT data FROM app.sessions WHERE session_id = %s", (sid,))
            result = cursor.fetchone()
            if result:
                data = json.loads(result[0])
                return self.session_class(data, sid=sid)
            else:
                return self.session_class(sid=sid, new=True)
        except Exception as e:
            print(f"Error opening session: {e}")
            return self.session_class(sid=sid, new=True)
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()

    def save_session(self, app, session, response):
        if not session:
            return

        connection = get_connection()
        cursor = connection.cursor()

        try:
            session_data = json.dumps(dict(session), cls=DateTimeUUIDEncoder)
            cursor.execute("""
                INSERT INTO app.sessions (session_id, user_id, data, created_at, updated_at)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (session_id) DO UPDATE
                SET data = EXCLUDED.data, updated_at = EXCLUDED.updated_at
            """, (session.sid, session.get('_user_id'), session_data, datetime.now(), datetime.now()))
            connection.commit()
        except Exception as e:
            print(f"Error saving session: {e}")
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()

        session_cookie_name = app.config.get('SESSION_COOKIE_NAME', 'session')
        expires = datetime.now(timezone.utc) + timedelta(minutes=30)
        response.set_cookie(session_cookie_name, session.sid, expires=expires)
