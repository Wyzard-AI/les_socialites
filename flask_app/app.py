### IMPORTS START ###
import os
import re
import json
import uuid
import requests

from openai import OpenAI

import gspread
from oauth2client.service_account import ServiceAccountCredentials
from google.cloud import secretmanager
from google.cloud.sql.connector import Connector, IPTypes

from datetime import datetime, timedelta, timezone

from pypdf import PdfReader
from docx import Document
from markdown2 import markdown
from urllib.parse import urljoin, urlparse

from flask import Flask, request, redirect, render_template, session, flash, url_for, send_from_directory
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_session import Session

from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

from custom_session import CloudSQLSessionInterface

from bs4 import BeautifulSoup

### FUNCTIONS START ###
def before_request():
    if not request.is_secure:
        url = request.url.replace("http://", "https://", 1)
        return redirect(url, code=301)

def restricted_access(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_email = current_user.email
        if user_email not in ADMIN_EMAILS:
            flash('Access denied. You do not have permission to access this page.')
            return redirect(url_for('login'))  # Redirect to a safe page if access is denied
        return f(*args, **kwargs)
    return decorated_function

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

def sanitize_content(content):
    # Remove null bytes and ensure the string is UTF-8 encoded
    if isinstance(content, bytes):
        # Decode bytes, ignoring invalid sequences
        content = content.decode('utf-8', errors='ignore')
    # Remove null bytes if any still exist
    content = content.replace('\x00', '')  # Removing null bytes
    return content

def save_conversation_to_db(user_id, session_id, role, content):
    sanitize_content(content)
    try:
        connection = get_connection()
        cursor = connection.cursor()
        insert_query = """
            INSERT INTO app.conversations (user_id, session_id, message_role, message_content)
            VALUES (%s, %s, %s, %s)
        """
        cursor.execute(insert_query, (user_id, session_id, role, content))
        connection.commit()
    except Exception as e:
        print(f"Error saving conversation to DB: {e}")
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

def load_conversation_from_db(user_id, session_id):
    try:
        connection = get_connection()
        cursor = connection.cursor()
        select_query = """
            SELECT message_role, message_content
            FROM app.conversations
            WHERE user_id = %s AND session_id = %s
            ORDER BY created_at ASC
        """
        cursor.execute(select_query, (user_id, session_id))
        rows = cursor.fetchall()
        conversation = [{'role': row[0], 'content': row[1]} for row in rows]
        return conversation
    except Exception as e:
        print(f"Error loading conversation from DB: {e}")
        return []
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

def sanitize_text(text, proper=False):
    # Replace newline and carriage return characters with spaces
    text = text.replace('\n', ' ').replace('\r', ' ')

    # Replace multiple spaces with a single space
    text = re.sub(r'\s+', ' ', text).strip()

    # If proper is True, capitalize the text properly
    if proper:
        # Simple capitalization logic
        words = text.split()
        result = []
        for word in words:
            if word.isupper() and len(word) > 1:  # Preserve uppercase abbreviations
                result.append(word)
            else:
                result.append(word.capitalize())
        text = ' '.join(result)

    return text

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_file(file):
    filename = secure_filename(file.filename)
    file_extension = os.path.splitext(filename)[1].lower()
    text = ""

    if file_extension == ".txt":
        text = file.read().decode("utf-8")
    elif file_extension == ".pdf":
        reader = PdfReader(file)
        text = " ".join(page.extract_text() for page in reader.pages if page.extract_text())
    elif file_extension == ".docx":
        doc = Document(file)
        text = " ".join(paragraph.text for paragraph in doc.paragraphs)
    return sanitize_content(text)

def get_openai_assistant_response(openai_client, conversation=None, category=None):
    user_id = current_user.id
    session_id = session.sid
    business_name = session.get('business_name')

    brand_voice = get_brand_voice(business_name)

    if brand_voice is None:
        brand_voice_instructions = ""
    else:
        brand_voice_instructions = f"Brand Voice Instructions: When answering the prompt please make all content you are giving me respects this tone of voice: {brand_voice} writing style"

    if conversation is None:
        conversation = load_conversation_from_db(user_id, session_id)

    # Check if the conversation is just starting and hasn't added system instructions yet
    if 'system' not in [message['role'] for message in conversation]:

        default_instructions = "There are no specific instructions."

        instructions = ""

        try:
            connection = get_connection()
            cursor = connection.cursor()

            # Fetch knowledge base instructions from Postgres
            if business_name:
                knowledge_query = """
                    SELECT STRING_AGG(knowledge_instructions, ' ') AS instructions
                    FROM app.knowledge_base
                    WHERE business_name = %s
                """
                cursor.execute(knowledge_query, (business_name,))
                knowledge_result = cursor.fetchone()

                if knowledge_result and knowledge_result[0]:
                    instructions += "Knowledge Base Instructions: " + knowledge_result[0] + " "

            # Fetch category-specific instructions from Postgres
            if category:
                category_query = """
                    SELECT instructions
                    FROM app.prompts
                    WHERE category = %s
                    LIMIT 1
                """
                cursor.execute(category_query, (category,))
                category_result = cursor.fetchone()

                if category_result and category_result[0]:
                    instructions += "Category-specific Instructions: " + category_result[0] + " "

        except Exception as e:
            print(f"Error: {e}")
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()

        instructions += brand_voice_instructions

        # If no instructions were found, use the default instructions
        if not instructions:
            instructions = default_instructions + brand_voice_instructions
        else:
            # Prepend context to the instructions
            instructions = f"""
            Every time you get a new prompt, you will potentially receive 3 different sets of instructions for it:

            1.Knowledge Base Instructions, 2.Category-specific Instructions, and 3.Brand Voice Instructions.

            Here is how to prioritize those instructions: 1, 2, 3.

            {instructions}
            """

        # Sanitize the instructions and add them to the conversation
        sanitized_instructions = sanitize_text(instructions)
        save_conversation_to_db(user_id, session_id, 'system', sanitized_instructions)

    # Workflow for if the conversation already has instructions
    else:
        if category:
            # Initialize the instructions variable
            instructions = ""

            try:
                # Establish the connection to the Postgres CloudSQL instance
                connection = get_connection()
                cursor = connection.cursor()

                # Fetch category-specific instructions from Postgres
                category_query = """
                    SELECT instructions
                    FROM app.prompts
                    WHERE category = %s
                    LIMIT 1
                """
                cursor.execute(category_query, (category,))
                category_result = cursor.fetchone()

                if category_result and category_result[0]:

                    instructions += "Category-specific Instructions: " + category_result[0] + " "

                    instructions += brand_voice_instructions

                    instructions = f"""
                    Every time you get a new prompt, you will potentially receive 3 different sets of instructions for it:

                    1.Knowledge Base Instructions, 2.Category-specific Instructions, and 3.Brand Voice Instructions.

                    Here is how to prioritize those instructions: 1, 2, 3.

                    {instructions}
                    """

                    # Sanitize the instructions and add them to the conversation
                    sanitized_instructions = sanitize_text(instructions)
                    save_conversation_to_db(user_id, session_id, 'system', sanitized_instructions)

            except Exception as e:
                print(f"Error: {e}")
            finally:
                if cursor:
                    cursor.close()
                if connection:
                    connection.close()

    # Call the OpenAI API with the entire conversation
    try:
        conversation = load_conversation_from_db(user_id, session_id)

        response = openai_client.chat.completions.create(
            model="gpt-4o",
            messages=conversation
        )

        assistant_response = response.choices[0].message.content

        return assistant_response
    except Exception as e:
        return f"An error occurred: {e}"

def summarize_scraped_text(text):
    # Ensure text isn't too long for the API
    if len(text) > 4096:
        text = text[:4096]  # Truncate text if needed

    response = openai_client.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "system", "content": "You are a helpful assistant that summarizes text."},
            {"role": "user", "content": f"Analyze the following text that was scraped from a business's website and summarize the business's goods and services in English: {text}"}
        ]
    )

    summary = response.choices[0].message.content
    return summary

def save_summary_to_db(url, summary):
    connection = get_connection()
    cursor = connection.cursor()

    id = str(uuid.uuid4())
    business_name = session.get('business_name')

    try:
        insert_query = """
            INSERT INTO app.summaries (id, business_name, url, summary, created_at)
            VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(insert_query, (id, business_name, url, summary, datetime.now()))
        connection.commit()
    except Exception as e:
        print(f"Error saving summary to DB: {e}")
        raise e
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

def get_categories_for_business_type(business_type):
    # Define a dictionary mapping business types to categories
    business_type_to_categories = {
        "Agriculture": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Automotive": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Banking and Finance": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Construction": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Creative Arts": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Energy": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Entertainment": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Environmental Services": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Fashion": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Food and Beverage": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Insurance": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Legal Services": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Logistics and Supply Chain": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Manufacturing": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Marketing and Advertising": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Media and Publishing": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Mining": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Nonprofit": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Real Estate": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Retail": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Technology": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Telecommunications": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Tourism": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Transportation": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Utilities": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Wellness and Fitness": ["Accounting", "Administrative Assistant", "Business Developer", "Customer Service", "Data Analyst", "Design", "HR", "Humanzier", "Legal Advisor", "Plagiarism Checker", "Project Manager", "Sales", "Spellcheck/Translation", "Personal Assistant"],
        "Les Socialites": ["Accounting", "Administrative Assistant", "Business Developer", "Content Creation", "Customer Service", "Data Analyst", "Design", "Event Planning", "HR", "Humanizer", "Influencer", "Influencer Marketing", "Legal Advisor", "Marketing", "Multi-Channel Campaign", "Plagiarism Checker", "PR", "Project Manager", "Sales", "SEO", "Social Media", "Spellcheck/Translation", "Personal Assistant", "Web", "eCommerce"]
    }

    # Return the categories for the selected business type

    business_type_categories = business_type_to_categories.get(business_type, [])

    return business_type_categories

def scrape_website(url, depth=1):
    visited_urls = set()
    scraped_text = []

    def scrape_page(url, current_depth):
        if current_depth > depth or url in visited_urls:
            return
        visited_urls.add(url)

        try:
            response = requests.get(url)
            response.raise_for_status()
        except requests.RequestException as e:
            print(f"Failed to fetch {url}: {e}")
            return

        soup = BeautifulSoup(response.text, 'html.parser')

        # Extract text from paragraphs
        paragraphs = soup.find_all('p')
        text = ' '.join(p.get_text() for p in paragraphs)
        scraped_text.append(text)

        # Find all links on the page
        links = soup.find_all('a', href=True)
        for link in links:
            href = link['href']
            # Construct a full URL
            full_url = urljoin(url, href)
            # Check if the link is part of the original domain
            if urlparse(full_url).netloc == urlparse(url).netloc:
                scrape_page(full_url, current_depth + 1)

    # Start scraping from the initial URL
    scrape_page(url, 1)

    return ' '.join(scraped_text)

def get_brand_voice(business_name):
    try:
        connection = get_connection()
        cursor = connection.cursor()

        # SQL query to retrieve the brand voice for the given business name
        select_query = """
            SELECT brand_voice
            FROM app.brand_voice
            WHERE business_name = %s
            LIMIT 1;
        """
        cursor.execute(select_query, (business_name,))
        result = cursor.fetchone()

        if result:
            brand_voice = result[0]  # Extract brand voice from the result
            return brand_voice
        else:
            return None  # Return None if no brand voice is found

    except Exception as e:
        print(f"An error occurred while retrieving the brand voice: {e}")
        return None

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()





### APP START ###
app = Flask(__name__)
app.secret_key = get_secret('les-socialites-app-secret-key')

ADMIN_EMAILS = ['renaudbeaupre1991@gmail.com', 'info@lessocialites.com']
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx'}

# Google Sheets setup
scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/drive"]

creds_json = get_secret('business-ops-service-account-json-key')
creds_dict = json.loads(creds_json)
creds = ServiceAccountCredentials.from_json_keyfile_dict(creds_dict, scope)

client = gspread.authorize(creds)

sheet = client.open("Wyzard Email List")
waitlist_sheet = sheet.worksheet("waitlist")
newsletter_sheet = sheet.worksheet("newsletter")

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.permanent_session_lifetime = timedelta(minutes=30)

# Using CloudSQL to manage server-side conversation storage and session management
app.session_interface = CloudSQLSessionInterface()

# Set config for custom session cookie name
app.config['SESSION_COOKIE_NAME'] = 'session'
# Set config for max size of document upload
app.config['MAX_CONTENT_LENGTH'] = 3 * 1024 * 1024
# Set config for cache duration of static files
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 86400 # 1 day in seconds

# CloudSQL Connection
connector = Connector()

# OpenAI API
openai_api_key = get_secret('les-socialites-openai-access-token')
openai_client = OpenAI(api_key=openai_api_key)





### LOGIN & SESSION MANAGEMENT ###
@app.before_request
def make_session_permanent():
    session.permanent = True

class User(UserMixin):
    def __init__(self, user_id, email, password, business_name, business_type):
        self.id = user_id
        self.email = email
        self.password = password
        self.business_name = business_name
        self.business_type = business_type

@login_manager.user_loader
def load_user(user_id):
    try:
        # Establish the connection to the Postgres CloudSQL instance
        connection = get_connection()
        cursor = connection.cursor()

        # Query the app.users table to find the user by ID
        query = """
            SELECT id, email, password, business_name, business_type
            FROM app.users
            WHERE id = %s
        """
        cursor.execute(query, (user_id,))
        result = cursor.fetchone()

        if not result:
            return None

        # Create and return a User object
        return User(user_id=result[0], email=result[1], password=result[2], business_name=result[3], business_type=result[4])

    except Exception as e:
        print(f"Error: {e}")
        return None

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        try:
            # Connect to the Postgres CloudSQL database
            connection = get_connection()
            cursor = connection.cursor()

            # Query CloudSQL for the user
            query = """
                SELECT id, email, password, business_name, business_type
                FROM app.users
                WHERE email = %s
                LIMIT 1
            """
            cursor.execute(query, (email,))
            result = cursor.fetchone()

            if not result:
                flash("Email or password is incorrect.")
                return redirect(url_for('login'))

            user_id, user_email, user_password, user_business_name, user_business_type = result
            user = User(user_id=user_id, email=user_email, password=user_password, business_name=user_business_name, business_type=user_business_type)

            if check_password_hash(user.password, password):
                login_user(user)
                session['business_name'] = user.business_name
                session['business_type'] = user.business_type
                return redirect(url_for('prompt_categories'))  # Redirect to the desired default page
            else:
                flash("Email or password is incorrect.")
                return redirect(url_for('login'))

        except Exception as e:
            print(f"An error occurred: {e}")
            return f"An error occurred during login: {e}", 500

        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Define a list of whitelisted email addresses for registration
    whitelisted_emails = [
        "renaudbeaupre1991@gmail.com",
        "info@lessocialites.com",
        "claudine@lessocialites.com",
        "tay@lessocialites.com",
        "jenny@lessocialites.com",
        "ruth@lessocialites.com",
        "imen@lessocialites.com",
        "felix@lessocialites.com",
        "karen@lessocialites.com",
        "ari@lessocialites.com",
        "genevieve.beaudry@gmail.com",
        "felix@lessocialites.com"
    ]

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        business_type = request.form['business_type']  # Capture the business_type from the form

        personal_domains = {'gmail', 'hotmail', 'yahoo', 'outlook', 'icloud', 'aol', 'live', 'msn'}

        domain = email.split('@')[1].split('.')[0]

        if domain in personal_domains:
            business_name = f"personal_account: {email}"
        else:
            business_name = domain

        # Check if the email is in the whitelist
        if email not in whitelisted_emails:
            flash("Your email is not authorized to register.", "error")
            return redirect(url_for('register'))

        # Check if the user is allowed to select "Les Socialites" as a business type based on email domain
        if business_type == "Les Socialites" and "lessocialites.com" not in email:
            flash("You are not authorized to select 'Les Socialites' as a business type.", "error")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

        try:
            # Connect to the Postgres CloudSQL database
            connection = get_connection()
            cursor = connection.cursor()

            # Check if the user already exists
            check_query = """
                SELECT id FROM app.users WHERE email = %s LIMIT 1
            """
            cursor.execute(check_query, (email,))
            result = cursor.fetchone()

            if result:
                flash("Email already exists.", "error")
                return redirect(url_for('register'))

            # Insert new user into CloudSQL
            user_id = str(uuid.uuid4())
            insert_query = """
                INSERT INTO app.users (id, email, password, business_name, business_type, timestamp)
                VALUES (%s, %s, %s, %s, %s, %s)
            """
            cursor.execute(insert_query, (user_id, email, hashed_password, business_name, business_type, datetime.now()))
            connection.commit()

        except Exception as e:
            print(f"An error occurred: {e}")
            return f"An error occurred during registration: {e}", 500

        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()

        # Flash success message with a 'success' category
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    # Check if the user should see "Les Socialites" as a business type option based on the domain
    email = request.args.get('email', '')
    is_socialites_whitelisted = "lessocialites.com" in email

    return render_template('register.html', is_socialites_whitelisted=is_socialites_whitelisted)

@app.route('/clear-conversation')
@login_required
def clear_conversation():
    user_id = current_user.id
    session_id = session.sid

    try:
        connection = get_connection()
        cursor = connection.cursor()
        delete_query = """
            DELETE FROM app.conversations
            WHERE user_id = %s AND session_id = %s
        """
        cursor.execute(delete_query, (user_id, session_id))
        connection.commit()
        flash('Conversation history cleared.')
    except Exception as e:
        print(f"Error clearing conversation: {e}")
        flash('Failed to clear conversation history.')
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    session.pop('conversation', None)

    return redirect('/results')

@app.route('/logout')
@login_required
def logout():
    user_id = current_user.id
    session_id = session.sid

    session.clear()

    connection = get_connection()
    cursor = connection.cursor()
    try:
        delete_conversations_query = """
            DELETE FROM app.conversations
            WHERE user_id = %s AND session_id = %s
        """
        cursor.execute(delete_conversations_query, (user_id, session_id))
        connection.commit()

        delete_sessions_query = """
            DELETE FROM app.sessions
            WHERE session_id = %s
        """
        cursor.execute(delete_sessions_query, (session_id,))
        connection.commit()
    except Exception as e:
        print(f"Error clearing conversation: {e}")
        connection.rollback()

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    logout_user()

    return redirect(url_for('login'))





### ROUTES PAGES ###
@app.route('/robots.txt')
def robots_txt():
    return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/results')
@login_required
def results():
    user_id = current_user.id
    session_id = session.sid

    conversation = load_conversation_from_db(user_id, session_id)

    for message in conversation:
        if message['role'] == 'assistant':
            message['content'] = markdown(message['content'])

    business_type = session.get('business_type', 'No business type selected')

    return render_template('results.html', conversation=conversation, business_type=business_type)

@app.route('/prompt-menu')
@login_required
def prompt_menu():
    category = request.args.get('category')

    # Retrieve the selected business type from the session
    business_type = session.get('business_type', 'No business type selected')

    # Get the categories for the selected business type
    categories = get_categories_for_business_type(business_type)

    categories_str = ', '.join(f"'{cat}'" for cat in categories)
    # Connect to the Postgres CloudSQL instance
    try:
        connection = get_connection()
        cursor = connection.cursor()

        # If a category is selected and it's valid for the business, fetch subcategories and prompts
        if category and category in categories:
            query = """
                SELECT subcategory, prompt, button_name
                FROM app.prompts
                WHERE category = %s
                ORDER BY subcategory, prompt
            """
            cursor.execute(query, (category,))
        else:
            # If no category is specified or invalid, fetch all prompts in valid categories
            query = f"""
                SELECT subcategory, prompt, button_name
                FROM app.prompts
                WHERE category IN ({categories_str})
                ORDER BY subcategory, prompt
            """
            cursor.execute(query)

        results = cursor.fetchall()

        # Organize prompts by subcategory
        prompts_by_subcategory = {}
        for row in results:
            subcategory, prompt, button_name = row[0], row[1], row[2]
            if subcategory not in prompts_by_subcategory:
                prompts_by_subcategory[subcategory] = []
            prompts_by_subcategory[subcategory].append({
                'prompt': prompt,
                'button_name': button_name
            })

        # Define the desired order of subcategories
        subcategory_order = ["Find", "Analyze", "Create", "Review"]

        # Sort the prompts by the desired subcategory order
        sorted_prompts_by_subcategory = {subcategory: prompts_by_subcategory[subcategory]
                                 for subcategory in subcategory_order
                                 if subcategory in prompts_by_subcategory}

        for subcategory, prompts in prompts_by_subcategory.items():
            if subcategory not in sorted_prompts_by_subcategory:
                sorted_prompts_by_subcategory[subcategory] = prompts

        return render_template('prompt_menu.html', category=category, prompts_by_subcategory=sorted_prompts_by_subcategory)

    except Exception as e:
        print(f"Error: {e}")
        return f"An error occurred: {e}", 500

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

@app.route('/prompt-categories')
@login_required
def prompt_categories():
    # Dictionary of categories with their corresponding emojis
    categories_with_emojis = {
        "Sales": "💰",
        "Marketing": "📣",
        "PR": "📰",
        "Social Media": "❤️",
        "Web": "🌐",
        "Legal Advisor": "⚖️",
        "Event Planning": "🎉",
        "Spellcheck/Translation": "✍️",
        "Multi-Channel Campaign": "💌",
        "HR": "💼",
        "SEO": "🔍",
        "Humanizer": "🧠",
        "eCommerce": "🛒",
        "Data Analyst": "📊",
        "Project Manager": "📋",
        "Customer Service": "📞",
        "Business Developer": "🤝",
        "Plagiarism Checker": "✅",
        "Influencer Marketing": "🤳",
        "Administrative Assistant": "💻",
        "Accounting": "📄",
        "Design": "🎨",
        "Personal Assistant": "🤖",
        "Content Creation": "📸",
        "Influencer": "🤩"
    }

    business_type = session.get('business_type', 'No business type selected')

    # Get the categories for the selected business type
    available_categories = get_categories_for_business_type(business_type)

    # Filter the categories with emojis based on the available categories
    categories_with_emojis_filtered = {
        category: categories_with_emojis.get(category, '')
        for category in available_categories
        if category in categories_with_emojis
    }

    return render_template('prompt_categories.html', categories_with_emojis=categories_with_emojis_filtered)

@app.route('/account-info')
@login_required
def account_info():
    # Retrieve the user_id from the session
    user_email = current_user.email  # Adjust based on how you store the user session data

    try:
        # Establish the connection to the Postgres CloudSQL instance
        connection = get_connection()
        cursor = connection.cursor()

        # Query to fetch the user's email, business_name, and business_type
        query = """
            SELECT email, business_name, business_type
            FROM app.users
            WHERE email = %s
        """
        cursor.execute(query, (user_email,))
        user_data = cursor.fetchone()

        # If user data is found, prepare it for display
        if user_data:
            email, business_name, business_type = user_data
            return render_template('account_info.html', email=email, business_name=business_name, business_type=business_type)
        else:
            # Handle case where user data isn't found
            return render_template('account_info.html', error="User data not found.")
    except Exception as e:
        print(f"Error querying the database: {e}")
        return render_template('account_info.html', error="An error occurred while retrieving your account information.")

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

@app.route('/forgot_password')
def forgot_password():
    return render_template('forgot_password.html')

@app.route('/legal')
@login_required
def legal():
    return render_template('legal.html')

@app.route('/knowledge-base')
@login_required
@restricted_access
def knowledge_base():
    return render_template('knowledge_base.html')

@app.route('/brand-voice')
@login_required
@restricted_access
def brand_voice():
    return render_template('brand_voice.html')

@app.route('/billing')
@login_required
def billing():
    return render_template('billing.html')

@app.route('/faq')
def faq():
    return render_template('faq.html')





### ROUTE REQUESTS ###
@app.route('/view-prompt', methods=['POST'])
@login_required
def view_prompt():
    # Get the prompt and category from the form
    prompt = request.form['prompt']
    category = request.form.get('category')

    # Generate or get session_id and user_id
    user_id = current_user.id
    session_id = session.sid

    file = request.files.get('file')
    if file and file.filename != '' and allowed_file(file.filename):
        file_text = extract_text_from_file(file)
        prompt += "\n\n" + file_text

    modified_prompt = f"Please answer the following prompt: {prompt}"

    # Save the user's prompt to the database
    save_conversation_to_db(user_id, session_id, 'user', modified_prompt)

    # Get the response from OpenAI, passing the category
    response = get_openai_assistant_response(openai_client, category=category)
    formatted_response = markdown(response)

    # Save the assistant's response to the database
    save_conversation_to_db(user_id, session_id, 'assistant', response)

    conversation = load_conversation_from_db(user_id, session_id)

    for message in conversation:
        if message['role'] == 'assistant':
            message['content'] = markdown(message['content'])

    # Check if the user is an admin
    user_email = current_user.email
    is_admin = user_email in ADMIN_EMAILS  # Replace with actual admin emails

    return render_template('results.html', prompt=prompt, response=formatted_response, conversation=conversation, is_admin=is_admin)

@app.route('/save-brand-voice', methods=['POST'])
def save_brand_voice():
    business_name = session.get('business_name')
    brand_voices = request.form.getlist('brand_voice')  # Get list of selected brand voices
    brand_voices_lower = [voice.lower() for voice in brand_voices]  # Convert each brand voice to lowercase
    brand_voices_str = ', '.join(brand_voices_lower) # Join into a comma-separated string
    brand_id = str(uuid.uuid4())  # Generate a unique UUID for the entry

    try:
        connection = get_connection()
        cursor = connection.cursor()

        insert_query = """
            INSERT INTO app.brand_voice (id, business_name, brand_voice, timestamp)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (business_name) DO UPDATE
            SET brand_voice = EXCLUDED.brand_voice, timestamp = EXCLUDED.timestamp
        """
        cursor.execute(insert_query, (brand_id, business_name, brand_voices_str, datetime.now()))
        connection.commit()

        flash('Brand voice(s) saved successfully!', 'success')
    except Exception as e:
        flash(f'An error occurred: {e}', 'danger')
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return redirect(url_for('brand_voice'))

@app.route('/submit-knowledge-instructions', methods=['POST'])
@login_required
def submit_knowledge_instructions():
    knowledge_instructions = request.form['knowledge_instructions']
    business_name = session.get('business_name')
    file = request.files.get('file')

    # Initialize text variable
    extracted_text = ""

    # Process the file if uploaded
    if file and file.filename != '' and allowed_file(file.filename):
        try:
            extracted_text = extract_text_from_file(file)
        except Exception as e:
            flash(f"An error occurred while processing the file: {e}")
            return redirect(url_for('knowledge_base'))

    # Combine manual instructions with extracted text
    combined_instructions = f"{knowledge_instructions}\n{extracted_text}".strip()

    # Ensure there is some instruction to insert
    if not combined_instructions:
        flash("No instructions provided.")
        return redirect(url_for('knowledge_base'))

    # SQL query to insert knowledge instructions into the table
    insert_query = """
        INSERT INTO app.knowledge_base (id, business_name, knowledge_instructions, timestamp)
        VALUES (%s, %s, %s, %s)
    """

    try:
        # Connect to the Postgres CloudSQL database
        connection = get_connection()
        cursor = connection.cursor()

        # Generate a new UUID for the instruction
        instruction_id = str(uuid.uuid4())

        # Execute the insert query
        cursor.execute(insert_query, (instruction_id, business_name, sanitize_text(combined_instructions), datetime.now()))
        connection.commit()

        flash("Knowledge instructions added successfully.")

    except Exception as e:
        print(f"An error occurred: {e}")
        flash(f"An error occurred: {e}")

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return redirect(url_for('knowledge_base'))

@app.route('/add-link', methods=['GET', 'POST'])
def add_link():
    if request.method == 'POST':
        url = request.form['url']
        try:
            # Scrape the website
            print('Initating scraping')
            scraped_text = scrape_website(url, depth=2)

            # Summarize the scraped text using ChatGPT
            print('Sending scraped text for summary')
            summary = summarize_scraped_text(scraped_text)

            # Save the summary to CloudSQL
            print('Saving summary')
            save_summary_to_db(url, summary)

            print('Website summarized and saved successfully!', 'success')
            return redirect(url_for('knowledge_base'))
        except Exception as e:
            print(f'An error occurred: {e}')
            return redirect(url_for('knowledge_base'))

    return render_template('knowledge_base.html')

@app.route('/waitlist', methods=['GET'])
def waitlist():
    return render_template('waitlist.html')

@app.route('/submit_waitlist', methods=['POST'])
def submit_waitlist():
    name = request.form['name']
    email = request.form['email']
    company_name = request.form['company_name']
    number_of_employees = request.form['number_of_employees']

    # Add data to the Google Sheet
    try:
        waitlist_sheet.append_row([name, email, company_name, number_of_employees])
        flash("You've been added to the waitlist!", "success")
    except Exception as e:
        flash(f"An error occurred: {e}", "error")

    return redirect(url_for('waitlist'))

@app.route('/forgot_password_submit', methods=['POST'])
def forgot_password_submit():
    email = request.form['email']

    # SQL query to delete the user from the app.users table
    delete_query = """
        DELETE FROM app.users WHERE email = %s
    """

    try:
        # Connect to the Postgres CloudSQL database
        connection = get_connection()
        cursor = connection.cursor()

        # Execute the delete query
        cursor.execute(delete_query, (email,))
        connection.commit()

        flash('Email deleted successfully. You can register a new account.', 'success')

    except Exception as e:
        print(f"An error occurred: {e}")
        flash(f'An error occurred while processing your request: {e}', 'error')
        return redirect(url_for('forgot_password'))

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    # Redirect to the registration page after deleting the email
    return redirect(url_for('register'))

@app.route('/submit_newsletter', methods=['POST'])
def submit_newsletter():
    email = request.form['email']

    # Add data to the Google Sheet
    try:
        newsletter_sheet.append_row([email])
        flash("You've been added to the newsletter!", "success")
    except Exception as e:
        flash(f"An error occurred: {e}", "error")

    return redirect(url_for('waitlist'))






















########## WYZARD MANAGEMENT FOR ADMINS ##########

@app.route('/')
@login_required
@restricted_access
def index():
    categories = ['Sales', 'Marketing', 'PR', 'Social Media', 'Web', 'Legal Advisor', 'Event Planning',
                'Spellcheck/Translation', 'Multi-Channel Campaign', 'HR', 'SEO', 'Humanizer',
                'eCommerce', 'Data Analyst', 'Project Manager', 'Customer Service', 'Business',
                'Business Developer', 'Plagiarism Checker', 'Influencer Marketing',
                'Administrative Assistant', 'Accounting', 'Design', 'Personal Assistant',
                'Content Creation', 'Influencer']
    return render_template('index.html', categories=categories)

@app.route('/submit-prompt', methods=['POST'])
@login_required
@restricted_access
def submit_prompt():
    prompt = request.form['prompt']
    category = request.form['category']
    subcategory = request.form.get('subcategory')
    button_name = request.form.get('button_name')

    if not prompt:
        return "Prompt cannot be empty", 400
    if not category:
        return "Category cannot be empty", 400

    sanitized_prompt = sanitize_text(prompt)
    sanitized_category = sanitize_text(category, proper=True)
    sanitized_subcategory = sanitize_text(subcategory, proper=True) if subcategory else None
    sanitized_button_name = sanitize_text(button_name, proper=True) if button_name else None
    prompt_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()

    # Define the SQL query for inserting the prompt data
    insert_query = """
        INSERT INTO app.prompts (id, prompt, category, subcategory, button_name, timestamp)
        VALUES (%s, %s, %s, %s, %s, %s)
    """

    # Data to be inserted
    data_to_insert = (
        prompt_id,
        sanitized_prompt,
        sanitized_category,
        sanitized_subcategory,
        sanitized_button_name,
        timestamp
    )

    try:
        # Connect to the Postgres CloudSQL instance
        connection = get_connection()
        cursor = connection.cursor()

        # Execute the insert query
        cursor.execute(insert_query, data_to_insert)

        # Commit the transaction
        connection.commit()

    except Exception as e:
        print(f"An error occurred: {e}")
        return "An error occurred while inserting the prompt data.", 500

    finally:
        # Close the cursor and connection
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return render_template('index.html')

@app.route('/assign-button-name', methods=['POST'])
@login_required
@restricted_access
def assign_button_name():
    prompt_id = request.form['prompt_id']
    button_name = request.form['button_name']

    if not prompt_id or not button_name:
        return "Prompt ID and button name cannot be empty", 400

    # SQL query to update the button_name for the specified prompt_id
    update_query = """
        UPDATE app.prompts
        SET button_name = %s
        WHERE id = %s
    """

    try:
        # Connect to the Postgres CloudSQL instance
        connection = get_connection()
        cursor = connection.cursor()

        # Execute the update query
        cursor.execute(update_query, (button_name, prompt_id))

        # Commit the transaction
        connection.commit()

    except Exception as e:
        print(f"An error occurred: {e}")
        return "An error occurred while updating the button name.", 500

    finally:
        # Close the cursor and connection
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return redirect('/delete-prompts')

@app.route('/manage-prompts')
@login_required
@restricted_access
def manage_prompts():
    selected_category = request.args.get('category')
    selected_subcategory = request.args.get('subcategory')

    # Connect to the Postgres CloudSQL instance
    try:
        connection = get_connection()
        cursor = connection.cursor()

        # Fetch categories for the dropdown
        categories_query = """
            SELECT DISTINCT category
            FROM app.prompts
            ORDER BY category
        """
        cursor.execute(categories_query)
        categories = [row[0] for row in cursor.fetchall()]

        # Fetch subcategories for the dropdown based on the selected category
        if selected_category:
            subcategory_query = """
                SELECT DISTINCT subcategory
                FROM app.prompts
                WHERE category = %s
                ORDER BY subcategory
            """
            cursor.execute(subcategory_query, (selected_category,))
        else:
            # Fetch all distinct subcategories if no category is selected
            subcategory_query = """
                SELECT DISTINCT subcategory
                FROM app.prompts
                ORDER BY subcategory
            """
            cursor.execute(subcategory_query)

        subcategories = [row[0] for row in cursor.fetchall()]

        # Construct the WHERE clause dynamically based on user selection
        where_clauses = []
        query_params = []

        if selected_category:
            where_clauses.append("category = %s")
            query_params.append(selected_category)

        if selected_subcategory:
            where_clauses.append("subcategory = %s")
            query_params.append(selected_subcategory)

        # Construct the final query
        if where_clauses:
            where_clause = " WHERE " + " AND ".join(where_clauses)
        else:
            where_clause = ""

        final_query = f"""
            SELECT id, prompt, category, subcategory, button_name
            FROM app.prompts
            {where_clause}
            ORDER BY category, subcategory
        """

        cursor.execute(final_query, tuple(query_params))
        prompts = cursor.fetchall()

        # Organize prompts by subcategory
        prompts_by_subcategory = {}
        for prompt in prompts:
            prompt_id, prompt_text, category, subcategory, button_name = prompt
            if subcategory not in prompts_by_subcategory:
                prompts_by_subcategory[subcategory] = []
            prompts_by_subcategory[subcategory].append({
                'id': prompt_id,
                'prompt': prompt_text,
                'category': category,
                'subcategory': subcategory,
                'button_name': button_name
            })

        return render_template('manage_prompts.html', prompts_by_subcategory=prompts_by_subcategory, categories=categories, subcategories=subcategories, selected_category=selected_category, selected_subcategory=selected_subcategory)

    except Exception as e:
        print(f"Error: {e}")
        return "An error occurred.", 500

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

@app.route('/delete-prompt', methods=['POST'])
@login_required
@restricted_access
def delete_prompt():
    prompt_id = request.form['prompt_id']

    if not prompt_id:
        return "Prompt ID is required", 400

    # SQL query to delete the prompt with the specified prompt_id
    delete_query = """
        DELETE FROM app.prompts
        WHERE id = %s
    """

    try:
        # Connect to the Postgres CloudSQL instance
        connection = get_connection()
        cursor = connection.cursor()

        # Execute the delete query
        cursor.execute(delete_query, (prompt_id,))

        # Commit the transaction
        connection.commit()

    except Exception as e:
        print(f"An error occurred: {e}")
        return f"An error occurred during prompt deletion: {e}", 500

    finally:
        # Close the cursor and connection
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return redirect('/manage-prompts')

@app.route('/edit-prompt', methods=['POST'])
@login_required
@restricted_access
def edit_prompt():
    prompt_id = request.form['prompt_id']
    new_prompt_text = request.form['new_prompt_text']

    if not prompt_id or not new_prompt_text:
        return "Prompt ID and new prompt text cannot be empty", 400

    # Debugging: Print the prompt_id and new_prompt_text
    print(f"Editing prompt: {prompt_id} with new text: {new_prompt_text}")

    # SQL query to update the prompt text for the specified prompt_id
    update_query = """
        UPDATE app.prompts
        SET prompt = %s
        WHERE id = %s
    """

    try:
        # Connect to the Postgres CloudSQL instance
        connection = get_connection()
        cursor = connection.cursor()

        # Execute the update query
        cursor.execute(update_query, (new_prompt_text, prompt_id))

        # Commit the transaction
        connection.commit()

        # Debugging: Confirm successful update
        print("Prompt update successful.")

    except Exception as e:
        print(f"An error occurred: {e}")
        return f"An error occurred during prompt update: {e}", 500

    finally:
        # Close the cursor and connection
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return redirect('/manage-prompts')

@app.route('/manage-categories')
@login_required
@restricted_access
def manage_categories():
    query = """
        SELECT DISTINCT category, subcategory
        FROM app.prompts
        ORDER BY category, subcategory
    """

    categories = {}

    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(query)
        results = cursor.fetchall()

        for row in results:
            category, subcategory = row
            if category not in categories:
                categories[category] = []
            if subcategory and subcategory not in categories[category]:
                categories[category].append(subcategory)

    except Exception as e:
        print(f"An error occurred: {e}")
        return f"An error occurred while fetching categories: {e}", 500

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return render_template('manage_categories.html', categories=categories)

@app.route('/manage-subcategories')
@login_required
@restricted_access
def manage_subcategories():
    category = request.args.get('category')

    if not category:
        return redirect('/manage-categories')

    query = """
        SELECT DISTINCT subcategory
        FROM app.prompts
        WHERE category = %s
        ORDER BY subcategory
    """

    subcategories = []

    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(query, (category,))
        subcategories = [row[0] for row in cursor.fetchall()]

    except Exception as e:
        print(f"An error occurred: {e}")
        return f"An error occurred while fetching subcategories: {e}", 500

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return render_template('manage_subcategories.html', category=category, subcategories=subcategories)

@app.route('/add-categories', methods=['POST'])
@login_required
@restricted_access
def add_categories():
    categories_input = request.form['categories']

    if not categories_input:
        return "No categories provided", 400

    categories = [category.strip() for category in categories_input.split(',')]
    sanitized_categories = [sanitize_text(category, proper=True) for category in categories]

    rows_to_insert = [
        (str(uuid.uuid4()), None, category, None, None, datetime.now())
        for category in sanitized_categories
    ]

    insert_query = """
        INSERT INTO app.prompts (id, prompt, category, subcategory, button_name, timestamp)
        VALUES (%s, %s, %s, %s, %s, %s)
    """

    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.executemany(insert_query, rows_to_insert)
        connection.commit()

    except Exception as e:
        print(f"An error occurred: {e}")
        return f"An error occurred while inserting categories: {e}", 500

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return redirect('/manage-categories')

@app.route('/add-subcategories', methods=['POST'])
@login_required
@restricted_access
def add_subcategories():
    category = request.form['category']
    subcategories_input = request.form['subcategories']  # Expecting a single input string

    if not category or not subcategories_input:
        return "Category and subcategories cannot be empty", 400

    # Split the input string by commas and strip any whitespace
    subcategories = [subcategory.strip() for subcategory in subcategories_input.split(',')]

    # Sanitize and prepare the subcategories
    sanitized_subcategories = [sanitize_text(subcategory, proper=True) for subcategory in subcategories]

    # Prepare the data to be inserted
    rows_to_insert = [
        (str(uuid.uuid4()), None, category, subcategory, None, datetime.now())
        for subcategory in sanitized_subcategories
    ]

    # SQL statement to insert data into the table
    insert_query = """
        INSERT INTO app.prompts (id, prompt, category, subcategory, button_name, timestamp)
        VALUES (%s, %s, %s, %s, %s, %s)
    """

    try:
        # Connect to the Postgres CloudSQL database
        connection = get_connection()
        cursor = connection.cursor()

        # Insert data into the table
        cursor.executemany(insert_query, rows_to_insert)
        connection.commit()

    except Exception as e:
        print(f"An error occurred: {e}")
        return f"An error occurred while adding subcategories: {e}", 500

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return redirect('/manage-categories')

@app.route('/edit-category', methods=['POST'])
@login_required
@restricted_access
def edit_category():
    old_category = request.form['old_category']
    new_category_name = request.form['new_category_name']

    if not old_category or not new_category_name:
        return "Category names cannot be empty", 400

    # Sanitize the new category name for proper capitalization
    new_category_name = sanitize_text(new_category_name, proper=True)

    # Update the category name in the table
    query = """
        UPDATE app.prompts
        SET category = %s
        WHERE category = %s
    """

    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(query, (new_category_name, old_category))
        connection.commit()

    except Exception as e:
        print(f"An error occurred: {e}")
        return f"An error occurred while editing the category: {e}", 500

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return redirect('/manage-categories')

@app.route('/edit-subcategory', methods=['POST'])
@login_required
@restricted_access
def edit_subcategory():
    category = request.form['category']
    old_subcategory = request.form['old_subcategory']
    new_subcategory_name = request.form['new_subcategory_name']

    if not category or not old_subcategory or not new_subcategory_name:
        return "Category, old subcategory, and new subcategory names cannot be empty", 400

    # Sanitize the new subcategory name for proper capitalization
    new_subcategory_name = sanitize_text(new_subcategory_name, proper=True)

    # Update the subcategory name in the table
    query = """
        UPDATE app.prompts
        SET subcategory = %s
        WHERE category = %s AND subcategory = %s
    """

    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(query, (new_subcategory_name, category, old_subcategory))
        connection.commit()

    except Exception as e:
        print(f"An error occurred: {e}")
        return f"An error occurred while editing the subcategory: {e}", 500

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return redirect('/manage-categories')

@app.route('/delete-category', methods=['POST'])
@login_required
@restricted_access
def delete_category():
    category = request.form['category']

    if not category:
        return "Category name cannot be empty", 400

    # Delete the selected category from the table
    query = """
        DELETE FROM app.prompts
        WHERE category = %s
    """

    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(query, (category,))
        connection.commit()

    except Exception as e:
        print(f"An error occurred: {e}")
        return f"An error occurred while deleting the category: {e}", 500

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return redirect('/manage-categories')

@app.route('/delete-subcategory', methods=['POST'])
@login_required
@restricted_access
def delete_subcategory():
    category = request.form['category']
    subcategory = request.form['subcategory']

    if not category or not subcategory:
        return "Category and subcategory names cannot be empty", 400

    # SQL query to update the table, setting the subcategory to NULL where it matches the category and subcategory
    update_query = """
        UPDATE app.prompts
        SET subcategory = NULL
        WHERE category = %s AND subcategory = %s
    """

    try:
        # Connect to the Postgres CloudSQL database
        connection = get_connection()
        cursor = connection.cursor()

        # Execute the update query
        cursor.execute(update_query, (category, subcategory))
        connection.commit()

    except Exception as e:
        print(f"An error occurred: {e}")
        return f"An error occurred while deleting the subcategory: {e}", 500

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return redirect('/manage-categories')

@app.route('/update-instructions', methods=['POST'])
@login_required
@restricted_access
def update_instructions():
    category = request.form['category']
    new_instructions = request.form['instructions']

    if not category or not new_instructions:
        return "Category and Instructions cannot be empty", 400

    # SQL query to update the instructions for the selected category
    update_query = """
        UPDATE app.prompts
        SET instructions = %s
        WHERE category = %s
    """

    try:
        # Connect to the Postgres CloudSQL database
        connection = get_connection()
        cursor = connection.cursor()

        # Execute the update query
        cursor.execute(update_query, (new_instructions, category))
        connection.commit()

    except Exception as e:
        print(f"An error occurred: {e}")
        return f"An error occurred while updating instructions: {e}", 500

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return redirect('/')

@app.route('/manage-knowledge-base', methods=['GET', 'POST'])
@login_required
@restricted_access
def manage_knowledge_base():
    # Retrieve selected business name from query parameters for filtering
    selected_business_name = request.args.get('filter_business_name', '')

    try:
        # Connect to the Postgres CloudSQL database
        connection = get_connection()
        cursor = connection.cursor()

        # Query to fetch knowledge instructions filtered by business name if selected
        query = """
            SELECT id, business_name, knowledge_instructions
            FROM app.knowledge_base
            WHERE (%s = '' OR business_name = %s)
            ORDER BY timestamp DESC
        """
        cursor.execute(query, (selected_business_name, selected_business_name))
        knowledge_instructions = [
            {"id": row[0], "business_name": row[1], "knowledge_instructions": row[2]}
            for row in cursor.fetchall()
        ]

        # Fetch distinct business names from CloudSQL for the dropdown
        business_names_query = """
            SELECT DISTINCT business_name
            FROM app.knowledge_base
            ORDER BY business_name
        """
        cursor.execute(business_names_query)
        business_names = [row[0] for row in cursor.fetchall()]

    except Exception as e:
        print(f"An error occurred: {e}")
        return f"An error occurred while managing the knowledge base: {e}", 500

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return render_template(
        'manage_knowledge_base.html',
        knowledge_instructions=knowledge_instructions,
        business_names=business_names,
        selected_business_name=selected_business_name
    )

@app.route('/submit-knowledge', methods=['POST'])
@login_required
@restricted_access
def submit_knowledge():
    knowledge_instructions = request.form['knowledge_instructions']
    business_name = request.form['business_name']

    # Insert into CloudSQL
    insert_query = """
        INSERT INTO app.knowledge_base (id, business_name, knowledge_instructions, timestamp)
        VALUES (%s, %s, %s, %s)
    """
    try:
        # Connect to the Postgres CloudSQL database
        connection = get_connection()
        cursor = connection.cursor()

        # Generate a new UUID for the instruction
        instruction_id = str(uuid.uuid4())

        # Execute the insert query
        cursor.execute(insert_query, (instruction_id, business_name, sanitize_text(knowledge_instructions), datetime.now()))
        connection.commit()

    except Exception as e:
        print(f"An error occurred: {e}")
        return f"An error occurred while submitting knowledge: {e}", 500

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return redirect(url_for('manage_knowledge_base', business_name=business_name))

@app.route('/delete-knowledge', methods=['POST'])
@login_required
@restricted_access
def delete_knowledge():
    instruction_id = request.form['id']

    # SQL query to delete the selected instruction from the table
    delete_query = """
        DELETE FROM app.knowledge_base WHERE id = %s
    """

    try:
        # Connect to the Postgres CloudSQL database
        connection = get_connection()
        cursor = connection.cursor()

        # Execute the delete query
        cursor.execute(delete_query, (instruction_id,))
        connection.commit()

    except Exception as e:
        print(f"An error occurred: {e}")
        return f"An error occurred while deleting knowledge: {e}", 500

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return redirect(url_for('manage_knowledge_base'))

if __name__ == '__main__':
    app.run(debug=True, port=5001)
