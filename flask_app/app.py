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

from datetime import datetime, timedelta

from pypdf import PdfReader
from docx import Document
from markdown2 import markdown
from urllib.parse import urljoin, urlparse

from flask import Flask, request, redirect, render_template, session, flash, url_for, send_from_directory, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

from custom_session import CloudSQLSessionInterface

from bs4 import BeautifulSoup





### GENERAL FUNCTIONS START ###
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
            SELECT message_role, message_content, created_at
            FROM app.conversations
            WHERE user_id = %s AND session_id = %s
            ORDER BY created_at ASC
        """
        cursor.execute(select_query, (user_id, session_id))
        rows = cursor.fetchall()
        conversation = [{'role': row[0], 'content': row[1], 'created_at': row[2]} for row in rows]

        # Separate system messages and other messages
        system_message = [msg for msg in conversation if msg['role'] == 'system']
        other_messages = [msg for msg in conversation if msg['role'] != 'system']

        # Combine system message (if any) at the start followed by other messages in order
        ordered_conversation = system_message + other_messages

        # Remove 'created_at' from the final conversation structure for simplicity
        for msg in ordered_conversation:
            del msg['created_at']

        return ordered_conversation
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



def get_openai_assistant_response(openai_client, conversation=None):
    user_id = current_user.id
    session_id = session.sid
    business_name = session.get('business_name')

    if conversation is None:
        conversation = load_conversation_from_db(user_id, session_id)

    # Check if the conversation is just starting and hasn't added system instructions yet
    if 'system' not in [message['role'] for message in conversation]:

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

        except Exception as e:
            print(f"Error: {e}")
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()

        brand_voice = get_brand_voice(business_name)

        if brand_voice is None:
            brand_voice_instructions = ""
        else:
            brand_voice_instructions = f"""Brand Voice Instructions:
            When the prompt is received, please analyze what kind of request it is. If and only if the request is about creating content (e.g. a social media post, blog articles, etc) please make sure you do it in this tone of voice: {brand_voice}."""

        instructions += brand_voice_instructions

        website_summary = get_website_summary(business_name)

        if website_summary is None:
            website_summary_instructions = ""
        else:
            website_summary_instructions = f"""Website Summary Instructions:
            When the prompt is received, analyze if it is about a website. If so, check to see if the following summary is related to the website in the prompt. If yes, then use this as the context for answering the prompt: {website_summary}."""

        instructions += website_summary_instructions

        if instructions == "":
            instructions = "There are no special instructions just answer the prompt."
        else:
            instructions = f"""
            At the beginning of the conversation, you will potentially receive 3 sets of instructions for answering subsequent prompts:

            1) Knowledge Base Instructions, 2) Brand Voice Instructions, and 3) Website Summary Instructions.

            Prioritize those instructions in this order: 1), 2), and then 3).

            Also, please do not hallucinate or attempt to lie when answering the prompts.

            {instructions}
            """

        # Sanitize the instructions and add them to the conversation
        sanitized_instructions = sanitize_text(instructions)
        save_conversation_to_db(user_id, session_id, 'system', sanitized_instructions)

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
        "Les Socialites": ["Accounting", "Administrative Assistant", "Business Developer", "Content Creation", "Customer Service", "Data Analyst", "Design", "Event Planning", "HR", "Humanizer", "Influencer", "Influencer Marketing", "Legal Advisor", "Marketing", "Multi-Channel Campaign", "Plagiarism Checker", "PR", "Project Manager", "Sales", "Social Media", "Spellcheck/Translation", "Personal Assistant", "Web", "eCommerce"]
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



def get_website_summary(business_name):
    try:
        connection = get_connection()
        cursor = connection.cursor()

        # SQL query to retrieve the website summary for the given business name
        select_query = """
            SELECT summary
            FROM app.summaries
            WHERE business_name = %s
            ORDER BY created_at DESC
            LIMIT 1;
        """
        cursor.execute(select_query, (business_name,))
        result = cursor.fetchone()

        if result:
            website_summary = result[0]  # Extract summary from the result
            return website_summary
        else:
            return None  # Return None if no summary is found

    except Exception as e:
        print(f"An error occurred while retrieving the website summary: {e}")
        return None

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()



def pass_prompt_to_retrieve_openai_assistant_response(prompt):
    # Generate or get session_id and user_id
    user_id = current_user.id
    session_id = session.sid

    # Save the user's prompt to the database
    save_conversation_to_db(user_id, session_id, 'user', prompt)

    # Get the response from OpenAI
    response = get_openai_assistant_response(openai_client)

    # Save the assistant's response to the database (original response, not split)
    save_conversation_to_db(user_id, session_id, 'assistant', response)

    # Load the entire conversation from the database for this session
    conversation = load_conversation_from_db(user_id, session_id)

    # Process the conversation for rendering
    for message in conversation:
        if message['role'] == 'assistant' and '```' in message['content']:
            parts = message['content'].split('```')
            message['content_parts'] = []
            for i, part in enumerate(parts):
                if i % 2 == 0:
                    message['content_parts'].append({'type': 'text', 'content': markdown(part)})
                else:
                    message['content_parts'].append({'type': 'code', 'content': part})
        else:
            message['content_parts'] = [{'type': 'text', 'content': markdown(message['content'])}]

    return conversation





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

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.permanent_session_lifetime = timedelta(minutes=720)

# Using CloudSQL to manage server-side conversation storage and session management
app.session_interface = CloudSQLSessionInterface()

# Set config for custom session cookie name
app.config['SESSION_COOKIE_NAME'] = 'session'
# Set config for max size of document upload
app.config['MAX_CONTENT_LENGTH'] = 3 * 1024 * 1024
# Set config for cache duration of static files
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 2592000

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
                return redirect(url_for('conversations'))  # Redirect to the desired default page
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
        "ari@lessocialites.com",
        "gladys@lessocialites.com",
        "michael@lessocialites.com",
        "genevieve.beaudry@gmail.com",
        "team@lessocialites.com",
        "test@lessocialites.com",
        "renaud.tester@gmail.com",
        "beaudrydiane6@gmail.com"
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

    return render_template('register.html')



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


@app.route('/app/conversations')
@login_required
def conversations():
    is_admin = current_user.email in ADMIN_EMAILS
    return render_template('app/conversations.html', is_admin=is_admin)



@app.route('/app/prompt-categories')
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

    return render_template('app/prompt_categories.html', categories_with_emojis=categories_with_emojis_filtered)



@app.route('/app/account-info')
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
            return render_template('app/account_info.html', email=email, business_name=business_name, business_type=business_type)
        else:
            # Handle case where user data isn't found
            flash("Account unsuccessfully retrieved! Please register", "error")
            return redirect(url_for('register'))
    except Exception as e:
        print(f"Error querying the database: {e}")
        flash("Database error! Please try logging in again", "error")
        return redirect(url_for('login'))

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()



@app.route('/forgot-password')
def forgot_password():
    return render_template('forgot_password.html')



@app.route('/app/product-legal')
@login_required
def product_legal():
    return render_template('app/product_legal.html')



@app.route('/app/brand-voice')
@login_required
def brand_voice():
    return render_template('app/brand_voice.html')



@app.route('/app/billing')
@login_required
def billing():
    return render_template('app/billing.html')



@app.route('/app/product-faq')
@login_required
def product_faq():
    return render_template('app/product_faq.html')





### ROUTE REQUESTS ###
@app.route('/get_prompts', methods=['GET'])
@login_required
def get_prompts():
    # Get the business type from the session
    business_type = session.get('business_type')

    if not business_type:
        return jsonify({"error": "Business type not found in session"}), 400

    # Get the allowed categories for the business type
    allowed_categories = get_categories_for_business_type(business_type)

    # Establish a database connection
    conn = get_connection()
    cursor = conn.cursor()

    # Query to fetch prompts from your table, filtering by the allowed categories
    query = """
    SELECT category, subcategory, button_name
    FROM app.prompts
    WHERE category = ANY(%s)
    """
    cursor.execute(query, (allowed_categories,))
    rows = cursor.fetchall()

    # Format the data as a dictionary
    prompts = {}
    for row in rows:
        category, subcategory, button_name = row
        if category not in prompts:
            prompts[category] = {}
        if subcategory not in prompts[category]:
            prompts[category][subcategory] = []
        prompts[category][subcategory].append(button_name)

    cursor.close()
    conn.close()
    return jsonify(prompts)



@app.route('/get_prompt_for_openai_assistant_response', methods=['GET'])
@login_required
def get_prompt_for_openai_assistant_response():
    category = request.args.get('category')
    subcategory = request.args.get('subcategory')
    button_name = request.args.get('button_name')

    if not (category and subcategory and button_name):
        return jsonify({"error": "Invalid parameters"}), 400

    # Establish a database connection
    conn = get_connection()
    cursor = conn.cursor()

    # Query to fetch the prompt for the given category, subcategory, and button_name
    query = """
    SELECT prompt
    FROM app.prompts
    WHERE category = %s AND subcategory = %s AND button_name = %s
    """
    cursor.execute(query, (category, subcategory, button_name))
    row = cursor.fetchone()

    cursor.close()
    conn.close()

    if row:
        prompt = row[0]

        # Pass the prompt to the assistant response function
        conversation = pass_prompt_to_retrieve_openai_assistant_response(prompt)
        # print("Conversation:", conversation)

        return jsonify({"conversation": conversation})
    else:
        return jsonify({"error": "Prompt not found"}), 404



@app.route('/send_typed_prompt_for_openai_assistant_response', methods=['POST'])
@login_required
def send_typed_prompt_for_openai_assistant_response():
    prompt = request.form.get('prompt')
    file = request.files.get('file')

    # If no prompt and no file, return an error
    if not prompt and not file:
        return jsonify({"error": "Prompt is required"}), 400

    # If no prompt but a file exists, set a default prompt
    if not prompt and file and file.filename != '' and allowed_file(file.filename):
        prompt = "Review the following document uploaded. If it's marked as being confidential, you have permission to analyze it."

    # Process the file if one is uploaded
    file_text = ''
    if file and file.filename != '' and allowed_file(file.filename):
        file_text = extract_text_from_file(file)
        prompt += "\n\n" + file_text

    # Pass the prompt to the assistant response function
    conversation = pass_prompt_to_retrieve_openai_assistant_response(prompt)
    # print("Conversation:", conversation)

    return jsonify({"conversation": conversation})



@app.route('/delete_conversation', methods=['POST'])
@login_required
def delete_conversation():
    user_id = current_user.id
    session_id = session.sid

    connection = get_connection()
    cursor = connection.cursor()
    try:
        delete_conversations_query = """
            DELETE FROM app.conversations
            WHERE user_id = %s AND session_id = %s
        """
        cursor.execute(delete_conversations_query, (user_id, session_id))
        connection.commit()
    except Exception as e:
        print(f"Error clearing conversation: {e}")
        connection.rollback()
        return jsonify({"error": "Error deleting conversation"}), 500
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return jsonify({"message": "Conversation deleted successfully"})



@app.route('/app/save-brand-voice', methods=['POST'])
@login_required
@restricted_access
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



@app.route('/app/knowledge-base', methods=['GET', 'POST'])
@login_required
def knowledge_base():
    # Get the business name from the session
    business_name = session.get('business_name')

    # Fetch existing knowledge instructions for the business name
    try:
        connection = get_connection()
        cursor = connection.cursor()
        query = """
            SELECT id, knowledge_instructions
            FROM app.knowledge_base
            WHERE business_name = %s
        """
        cursor.execute(query, (business_name,))
        instructions = cursor.fetchall()  # List of (id, instruction) tuples

    except Exception as e:
        flash(f"Error fetching instructions: {e}", "danger")
        instructions = []
    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return render_template('app/knowledge_base.html', instructions=instructions)



@app.route('/app/submit-knowledge-instructions', methods=['POST'])
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



@app.route('/app/delete-knowledge-instructions', methods=['POST'])
@login_required
def delete_knowledge_instructions():
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
        flash('Instruction deleted successfully!', 'success')

    except Exception as e:
        flash(f"Error deleting instruction: {e}", 'danger')

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

    return redirect(url_for('knowledge_base'))



@app.route('/app/add-link', methods=['GET', 'POST'])
@login_required
@restricted_access
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

    return redirect(url_for('knowledge_base'))



@app.route('/waitlist', methods=['GET'])
def waitlist():
    return render_template('waitlist.html')



@app.route('/submit-waitlist', methods=['POST'])
def submit_waitlist():
    name = request.form['name']
    email = request.form['email']
    company_name = request.form['company_name']
    number_of_employees = request.form['number_of_employees']

    sheet = client.open("Wyzard Email List")
    waitlist_sheet = sheet.worksheet("waitlist")

    # Add data to the Google Sheet
    try:
        waitlist_sheet.append_row([name, email, company_name, number_of_employees])
        # flash("You've been added to the waitlist!", "success")
        flash("You've been added to the beta test!", "success")
    except Exception as e:
        flash(f"An error occurred: {e}", "error")

    return redirect(url_for('login'))



@app.route('/submit-newsletter', methods=['POST'])
def submit_newsletter():
    email = request.form.get('email')

    sheet = client.open("Wyzard Email List")
    newsletter_sheet = sheet.worksheet("newsletter")

    if not email:
        return jsonify({"success": False, "message": "Email is required"}), 400

    # Access the Google Sheets
    try:
        # Append the new email to the next available row
        newsletter_sheet.append_row([email])
        print("Email successfully subscribed!")
        return jsonify({"success": True, "message": "Subscription successful!"}), 200
    except Exception as e:
        print(f"Error subscribing email: {e}")
        return jsonify({"success": False, "message": "An error occurred. Please try again later."}), 500



@app.route('/forgot-password-submit', methods=['POST'])
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






























########## WYZARD MARKETING SITE ##########
@app.route('/')
def homepage():
    return render_template('homepage.html')

@app.route('/features')
def features():
    return render_template('features.html')

@app.route('/case-studies')
def case_studies():
    return render_template('case_studies.html')

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/faq')
def faq():
    return render_template('faq.html')

@app.route('/blog')
def blog():
    return render_template('blog.html')

@app.route('/get-started')
def get_started():
    return render_template('get_started.html')

@app.route('/about-us')
def about_us():
    return render_template('about_us.html')

@app.route('/watch-demo')
def watch_demo():
    return render_template('watch_demo.html')

@app.route('/contact_us')
def contact_us():
    return render_template('contact_us.html')

@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/terms-conditions')
def terms_conditions():
    return render_template('terms_conditions.html')



if __name__ == '__main__':
    app.run(debug=True)
