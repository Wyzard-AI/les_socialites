### IMPORTS START ###
import os
import re
import uuid
from pypdf import PdfReader
from flask import Flask, request, redirect, render_template, session, flash, url_for, send_from_directory
from google.cloud import bigquery, secretmanager
from google.cloud.sql.connector import Connector, IPTypes
from datetime import datetime, timedelta
from openai import OpenAI
from werkzeug.utils import secure_filename
from docx import Document
from markdown2 import markdown
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

### FUNCTIONS START ###
def get_connection():
    return connector.connect(
        "les-socialites-chat-gpt:us-east1:wyzard",  # Replace with your actual instance connection name
        "pg8000",  # This is the PostgreSQL driver for Cloud SQL
        user="postgres",
        password=get_secret('cloudsql-postgres-user-password'),  # Securely store and retrieve from environment variables
        db="wyzard_flask",
        ip_type=IPTypes.PUBLIC,  # or IPTypes.PRIVATE for private IP
    )

def get_secret(secret_name):
    secret_client = secretmanager.SecretManagerServiceClient()
    secret_resource_name = f"projects/916481347801/secrets/{secret_name}/versions/1"
    response = secret_client.access_secret_version(name=secret_resource_name)
    secret_payload = response.payload.data.decode('UTF-8')
    return secret_payload

def fetch_prompts_from_postgres(category=None, subcategory=None):
    # Create the base SQL query
    query = f"""
        SELECT id, prompt, category, subcategory, button_name
        FROM app.prompts
    """

    query_params = []
    conditions = []

    # Add filtering conditions if category or subcategory are provided
    if category:
        conditions.append("category = %s")
        query_params.append(category)

    if subcategory:
        conditions.append("subcategory = %s")
        query_params.append(subcategory)

    # Combine conditions with AND and add to the query
    if conditions:
        query += " WHERE " + " AND ".join(conditions)

    query += " ORDER BY category, subcategory"

    try:
        # Establish the connection to the Postgres CloudSQL instance
        connection = get_connection()
        cursor = connection.cursor()

        # Execute the query with parameters
        cursor.execute(query, tuple(query_params))
        results = cursor.fetchall()

        # Process the results
        prompts = []
        for row in results:
            prompts.append({
                "id": row[0],
                "prompt": row[1],
                "category": row[2],
                "subcategory": row[3],
                "button_name": row[4]
            })

        return prompts

    except Exception as e:
        print(f"Error: {e}")
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

def get_openai_assistant_response(conversation, openai_client, category=None):
    # Check if the conversation is just starting and hasn't added system instructions yet
    if 'system' not in [message['role'] for message in conversation]:
        # Default instructions
        default_instructions = "You are a manager at an influencer marketing company that does business in Canada and the United States."

        # Initialize the instructions variable
        instructions = ""

        # Retrieve business_name from the session
        business_name = session.get('business_name')

        try:
            # Establish the connection to the Postgres CloudSQL instance
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
                    instructions += "Knowledge Base Instruction: " + knowledge_result[0] + " "

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
                    instructions += "Category-Specific Instruction: " + category_result[0] + " "

        except Exception as e:
            print(f"Error: {e}")
        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()

        # If no instructions were found, use the default instructions
        if not instructions:
            instructions = "Default Instruction: " + default_instructions
        else:
            # Prepend context to the instructions
            instructions = f"Here are the instructions: {instructions}"

        # Sanitize the instructions and add them to the conversation
        sanitized_instructions = sanitize_text(instructions)
        conversation.insert(0, {"role": "system", "content": sanitized_instructions})

    # Call the OpenAI API with the entire conversation
    try:
        response = openai_client.chat.completions.create(
            model="gpt-4o",
            messages=conversation
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"An error occurred: {e}"

def extract_text_from_file(file):
    filename = secure_filename(file.filename)
    file_extension = os.path.splitext(filename)[1].lower()
    text = ""

    if file_extension == ".txt":
        text = file.read().decode("utf-8")
    elif file_extension == ".pdf":
        reader = PdfReader(file)
        for page in reader.pages:
            text += page.extract_text()
    elif file_extension == ".docx":
        doc = Document(file)
        for paragraph in doc.paragraphs:
            text += paragraph.text
    return text

def sanitize_business(business_name):
    # List of common stopwords to remove
    stopwords = {"the", "and", "of", "for", "to", "a", "an"}

    # Convert to lowercase to standardize
    cleaned_name = business_name.lower()

    # Remove punctuation and special characters except for spaces
    cleaned_name = re.sub(r'[^\w\s]', '', cleaned_name)

    # Split the name into words and filter out stopwords
    words = cleaned_name.split()
    filtered_words = [word for word in words if word not in stopwords]

    # Rejoin the filtered words and remove extra whitespace
    cleaned_name = ' '.join(filtered_words).strip()

    return cleaned_name

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
    return business_type_to_categories.get(business_type, [])

def restricted_access(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_email = session.get('user_email')
        if user_email not in ADMIN_EMAILS:
            flash('Access denied. You do not have permission to access this page.')
            return redirect(url_for('results'))  # Redirect to a safe page if access is denied
        return f(*args, **kwargs)
    return decorated_function

### APP START ###
app = Flask(__name__)

app.secret_key = get_secret('les-socialites-app-secret-key')

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.permanent_session_lifetime = timedelta(minutes=10)

# Set maximum file size to 16MB
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

connector = Connector()

# postgres_config = {
#     'user': 'postgres',
#     'password': get_secret('cloudsql-postgres-user-password'),
#     'dbname': 'wyzard_flask',
#     'host': '/cloudsql/les-socialites-chat-gpt:us-east1:wyzard',
#     'port': 5432  # Default PostgreSQL port
# }

openai_api_key = get_secret('les-socialites-openai-access-token')
openai_client = OpenAI(api_key=openai_api_key)

ADMIN_EMAILS = ['renaudbeaupre1991@gmail.com', 'info@lessocialites.com']

# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'wyzard.feedback@gmail.com'
app.config['MAIL_PASSWORD'] = get_secret('wyzard-email-app-password')
app.config['MAIL_DEFAULT_SENDER'] = 'wyzard.feedback@gmail.com'

mail = Mail(app)

@app.before_request
def make_session_permanent():
    session.permanent = True

class User(UserMixin):
    def __init__(self, user_id, email, password, business_name):
        self.id = user_id
        self.email = email
        self.password = password
        self.business_name = business_name

def before_request():
    if not request.is_secure:
        url = request.url.replace("http://", "https://", 1)
        return redirect(url, code=301)

@login_manager.user_loader
def load_user(user_id):
    try:
        # Establish the connection to the Postgres CloudSQL instance
        connection = get_connection()
        cursor = connection.cursor()

        # Query the app.users table to find the user by ID
        query = """
            SELECT id, email, password, business_name
            FROM app.users
            WHERE id = %s
        """
        cursor.execute(query, (user_id,))
        result = cursor.fetchone()

        if not result:
            return None

        # Create and return a User object
        return User(user_id=result[0], email=result[1], password=result[2], business_name=result[3])

    except Exception as e:
        print(f"Error: {e}")
        return None

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

@app.route('/robots.txt')
@login_required
@restricted_access
def robots_txt():
    return send_from_directory(app.static_folder, 'robots.txt')

@app.route('/')
@login_required
@restricted_access  # This decorator restricts access based on email
def index():
    categories = ['Sales',
                'Marketing',
                'PR',
                'Social Media',
                'Web',
                'Legal Advisor',
                'Event Planning',
                'Spellcheck/Translation',
                'Multi-Channel Campaign',
                'HR',
                'SEO',
                'Humanizer',
                'eCommerce',
                'Data Analyst',
                'Project Manager',
                'Customer Service',
                'Business',
                'Business Developer',
                'Plagiarism Checker',
                'Influencer Marketing',
                'Administrative Assistant',
                'Accounting',
                'Design',
                'Personal Assistant',
                'Content Creation',
                'Influencer']
    return render_template('index.html', categories=categories)

@app.route('/results')
@login_required
def results():
    # Retrieve the conversation from the session
    conversation = session.get('conversation', [])

    # Retrieve the selected business type from the session
    business_type = session.get('business_type', 'No business type selected')

    # Pass both the conversation and the business type to the results.html template
    return render_template('results.html', conversation=conversation, business_type=business_type)

@app.route('/clear-conversation')
@login_required
def clear_conversation():
    # Clear the session data to start a new conversation
    session.pop('conversation', None)
    return redirect('/view-prompt')





### ROUTES FOR PROMPTS ###

@app.route('/prompt-menu')
@login_required
def prompt_menu():
    category = request.args.get('category')

    # Retrieve the selected business type from the session
    business_type = session.get('business_type', 'No business type selected')

    # Get the categories for the selected business type
    categories = get_categories_for_business_type(business_type)

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
            query = """
                SELECT category, subcategory, prompt, button_name
                FROM app.prompts
                WHERE category = ANY(%s)
                ORDER BY category, subcategory, prompt
            """
            cursor.execute(query, (tuple(categories),))

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
        sorted_prompts_by_subcategory = {subcategory: prompts_by_subcategory[subcategory] for subcategory in subcategory_order if subcategory in prompts_by_subcategory}

        return render_template('prompt_menu.html', category=category, prompts_by_subcategory=sorted_prompts_by_subcategory)

    except Exception as e:
        print(f"Error: {e}")
        return f"An error occurred: {e}", 500

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

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

    # Prepare the conversation without adding instructions here
    modified_prompt = f"Here is the prompt, please answer based on the instructions provided: {prompt}"
    conversation = [{"role": "user", "content": modified_prompt}]

    # Call the get_openai_assistant_response function to handle instructions
    response = get_openai_assistant_response(conversation, openai_client, category=sanitized_category)
    formatted_response = markdown(response)

    # Append the assistant's response to the conversation
    conversation.append({"role": "assistant", "content": formatted_response})

    # Store the conversation in the session
    session['conversation'] = conversation

    # Render the results.html template with the conversation details
    return render_template('results.html', prompt=prompt, response=formatted_response, conversation=conversation)

@app.route('/view-prompt', methods=['GET', 'POST'])
@login_required
def view_prompt():
    if request.method == 'POST':
        # Get the prompt, category, and business type from the form
        prompt = request.form['prompt']
        category = request.form.get('category')  # Assuming category is provided

        # Get the previous conversation from the session
        conversation = session.get('conversation', [])

        file = request.files.get('file')
        if file and file.filename != '':
            file_text = extract_text_from_file(file)
            prompt += "\n\n" + file_text

        # Append the user's prompt (including file content if applicable) to the conversation
        modified_prompt = f"Here is the prompt, please answer based on the instructions provided: {prompt}"
        conversation.append({"role": "user", "content": modified_prompt})

        # Get the response from OpenAI, passing the category and business_type
        response = get_openai_assistant_response(conversation, openai_client, category=category)
        formatted_response = markdown(response)

        # Append the assistant's response to the conversation
        conversation.append({"role": "assistant", "content": formatted_response})

        # Save the conversation to the session
        session['conversation'] = conversation

        # Check if the user is an admin
        user_email = current_user.email
        is_admin = user_email in ADMIN_EMAILS  # Replace with actual admin emails

        return render_template('results.html', prompt=prompt, response=formatted_response, conversation=conversation, is_admin=is_admin)

    else:
        # Clear the conversation if this is a GET request to start a new conversation
        session.pop('conversation', None)
        # Render results.html with an empty conversation and no prompt/response
        return render_template('results.html', conversation=[], prompt='', response='')

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





### ROUTES FOR CATEGORIES ###

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





### ROUTES FOR INSTRUCTIONS ###

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





### ROUTES FOR FEEDBACK/MAIL ###

@app.route('/feedback')
@login_required
def feedback():
    return render_template('feedback.html')

@app.route('/send-feedback', methods=['POST'])
@login_required
def send_feedback():
    # Retrieve form data
    message_content = request.form.get('message')
    subject = request.form.get('subject')

    # Validate form data
    if not message_content or not subject:
        flash("All fields are required.")
        return redirect(url_for('feedback'))

    # Send email
    try:
        msg = Message(subject=f"{subject}", recipients=["info@lessocialites.com"])
        msg.body = message_content
        mail.send(msg)
        flash("Thank you for your feedback! Your message has been sent.")
    except Exception as e:
        flash(f"An error occurred while sending your message: {str(e)}")
        return redirect(url_for('feedback'))

    return redirect(url_for('feedback'))





### ROUTES FOR LOGIN/REGISTRATION ###

@app.route('/register', methods=['GET', 'POST'])
def register():
    # Define a list of whitelisted email addresses
    whitelisted_emails = [
        "renaudbeaupre1991@gmail.com",
        "info@lessocialites.com",
        "claudine@lessocialites.com",
        "tay@lessocialites.com",
        "jenny@lessocialites.com",
        "ruth@lessocialites.com",
        "imen@lessocialites.com",
        "wyzard.feedback@gmail.com",
        "felix@lessocialites.com",
        "karen@lessocialites.com",
        "ari@lessocialites.com"
    ]

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        business_name = request.form['business_name']

        # Check if the email is in the whitelist
        if email not in whitelisted_emails:
            flash("Your email is not authorized to register.", "error")
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
                INSERT INTO app.users (id, email, password, business_name, timestamp)
                VALUES (%s, %s, %s, %s, %s)
            """
            cursor.execute(insert_query, (user_id, email, hashed_password, sanitize_business(business_name), datetime.now()))
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
                SELECT id, email, password, business_name FROM app.users WHERE email = %s LIMIT 1
            """
            cursor.execute(query, (email,))
            result = cursor.fetchone()

            if not result:
                flash("Email or password is incorrect.")
                return redirect(url_for('login'))

            user_id, user_email, user_password, user_business_name = result
            user = User(user_id=user_id, email=user_email, password=user_password, business_name=user_business_name)

            if check_password_hash(user.password, password):
                login_user(user)
                session['user_email'] = user.email  # Store the email in the session
                session['business_name'] = user.business_name  # Store the business name in the session
                return redirect(url_for('business_type'))
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

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))





### ROUTES FOR KNOWLEDGE BASE ###

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

@app.route('/submit-knowledge-instructions', methods=['POST'])
@login_required
def submit_knowledge_instructions():
    knowledge_instructions = request.form['knowledge_instructions']
    business_name = session.get('business_name')

    if not business_name:
        flash("Business name not found in session.")
        return redirect(url_for('business_type'))

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
        cursor.execute(insert_query, (instruction_id, business_name, sanitize_text(knowledge_instructions), datetime.now()))
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

    return redirect(url_for('prompt_categories'))





### ROUTES FOR BUSINESS TYPE ###

@app.route('/business-type', methods=['GET', 'POST'])
@login_required
def business_type():
    if request.method == 'POST':
        # Store the selected business type in the session
        selected_type = request.form['business_type']
        session['business_type'] = selected_type

        # Redirect to the results page after selection
        return redirect(url_for('prompt_categories'))

    # Dictionary of business types with their corresponding emojis
    business_types_with_emojis = {
        "Agriculture": "🌾",
        "Automotive": "🚗",
        "Banking and Finance": "🏦",
        "Construction": "🏗️",
        "Creative Arts": "🎨",
        "Energy": "⚡",
        "Entertainment": "🎭",
        "Environmental Services": "🌍",
        "Fashion": "👗",
        "Food and Beverage": "🍔",
        "Insurance": "🛡️",
        "Legal Services": "⚖️",
        "Logistics and Supply Chain": "📦",
        "Manufacturing": "🏭",
        "Marketing and Advertising": "📢",
        "Media and Publishing": "📰",
        "Mining": "⛏️",
        "Nonprofit": "🎗️",
        "Real Estate": "🏠",
        "Retail": "🛍️",
        "Technology": "💻",
        "Telecommunications": "📡",
        "Tourism": "✈️",
        "Transportation": "🚚",
        "Utilities": "💡",
        "Wellness and Fitness": "💪",
        "Les Socialites": "👑"
    }

    # Render the business_type.html template, passing the dictionary of business types with emojis
    return render_template('business_type.html', business_types_with_emojis=business_types_with_emojis)

if __name__ == '__main__':
    app.run(debug=True, port=5001)
