### IMPORTS START ###
import os
import json
import re
import uuid
from pypdf import PdfReader
from flask import Flask, request, redirect, render_template, session, flash, url_for
from google.cloud import bigquery, secretmanager
from google.oauth2 import service_account
from datetime import datetime, timedelta
from openai import OpenAI
from werkzeug.utils import secure_filename
from docx import Document
from markdown2 import markdown
from flask_mail import Mail, Message
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash


### FUNCTIONS START ###
def get_secret(secret_name):
    secret_client = secretmanager.SecretManagerServiceClient()
    secret_resource_name = f"projects/916481347801/secrets/{secret_name}/versions/1"
    response = secret_client.access_secret_version(name=secret_resource_name)
    secret_payload = response.payload.data.decode('UTF-8')
    return secret_payload

def fetch_prompts_from_bigquery(project_id, dataset_id, table_id, category=None, subcategory=None):
    table_ref = f"`{project_id}.{dataset_id}.{table_id}`"

    query = f"""
        SELECT id, prompt, category, subcategory, button_name
        FROM {table_ref}
    """

    query_params = []
    if category:
        query += " WHERE category = @category"
        query_params.append(bigquery.ScalarQueryParameter("category", "STRING", category))

    if subcategory:
        query += " AND subcategory = @subcategory"
        query_params.append(bigquery.ScalarQueryParameter("subcategory", "STRING", subcategory))

    query += "ORDER BY category, subcategory"

    if query_params:
        query_config = bigquery.QueryJobConfig(query_parameters=query_params)
    else:
        query_config = None  # Ensure query_config is None if no parameters

    query_job = bigquery_client.query(query, job_config=query_config)
    results = query_job.result()

    if results is None:
        return []

    prompts = []
    for row in results:
        prompts.append({
            "id": row.id,
            "prompt": row.prompt,
            "category": row.category,
            "subcategory": row.subcategory,
            "button_name": row.button_name
        })

    return prompts

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

def get_openai_assistant_response(project_id, conversation, openai_client, category=None):
    # Check if the conversation is just starting and hasn't added system instructions yet
    if 'system' not in [message['role'] for message in conversation]:
        # Default instructions
        default_instructions = "You are a manager at an influencer marketing company that does business in Canada and the United States."

        # Initialize the instructions variable
        instructions = ""

        # Fetch knowledge base instructions from BigQuery based on the project_id
        knowledge_query = f"""
            SELECT STRING_AGG(knowledge_instructions, ' ') AS instructions
            FROM `{project_id}.prompt_manager.knowledge_base`
            WHERE business_id = @business_id
        """
        knowledge_query_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("business_id", "STRING", sanitize_project(project_id))
            ]
        )
        knowledge_query_job = bigquery_client.query(knowledge_query, job_config=knowledge_query_config)
        knowledge_result = knowledge_query_job.result()

        for row in knowledge_result:
            if row.instructions:
                instructions += "Knowledge Base Instruction: " + row.instructions + " "

        # Fetch category-specific instructions from BigQuery
        if category:
            category_query = f"""
                SELECT instructions
                FROM `{project_id}.{dataset_id}.{table_id}`
                WHERE category = @category
                LIMIT 1
            """
            category_query_config = bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter("category", "STRING", category)
                ]
            )
            category_query_job = bigquery_client.query(category_query, job_config=category_query_config)
            category_result = category_query_job.result()

            for row in category_result:
                if row.instructions:
                    instructions += "Category-Specific Instruction: " + row.instructions + " "

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

def sanitize_project(project_name):
    # Remove the string "chat-gpt"
    sanitized_name = project_name.replace("chat-gpt", "")

    # Remove any numbers followed by a hyphen
    sanitized_name = re.sub(r'-\d+', '', sanitized_name)

    # Remove any trailing hyphens or spaces that might be left after removal
    sanitized_name = sanitized_name.rstrip('-').strip()

    return sanitized_name


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

project_id = 'les-socialites-chat-gpt'
dataset_id = 'prompt_manager'
table_id = 'prompts'

bigquery_service_key = get_secret('les-socialites-bigquery-service-account-key')
service_account_info = json.loads(bigquery_service_key)
credentials = service_account.Credentials.from_service_account_info(service_account_info)
bigquery_client = bigquery.Client(credentials=credentials, project=service_account_info['project_id'])

openai_api_key = get_secret('les-socialites-openai-access-token')
openai_client = OpenAI(api_key=openai_api_key)

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
    def __init__(self, user_id, email, password):
        self.id = user_id
        self.email = email
        self.password = password

@login_manager.user_loader
def load_user(user_id):
    # Query BigQuery to find the user by ID
    query = f"""
        SELECT id, email, password
        FROM `{project_id}.{dataset_id}.users`
        WHERE id = @user_id
    """
    query_job = bigquery_client.query(query, job_config=bigquery.QueryJobConfig(
        query_parameters=[bigquery.ScalarQueryParameter("user_id", "STRING", user_id)]
    ))
    result = query_job.result()

    if not result:
        return None

    row = list(result)[0]
    return User(user_id=row.id, email=row.email, password=row.password)

@app.route('/')
@login_required
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

    return render_template('results.html', conversation=conversation)

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

    if category:
        # Fetch distinct subcategories and their associated prompts based on the selected category
        query = f"""
            SELECT subcategory, prompt, button_name
            FROM `{project_id}.{dataset_id}.{table_id}`
            WHERE category = @category
            ORDER BY subcategory, prompt
        """
        query_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("category", "STRING", category)
            ]
        )
    else:
        # Fetch all prompts when no category is specified
        query = f"""
            SELECT category, subcategory, prompt, button_name
            FROM `{project_id}.{dataset_id}.{table_id}`
            ORDER BY category, subcategory, prompt
        """
        query_config = None  # No query parameters needed for this query

    query_job = bigquery_client.query(query, job_config=query_config)

    # Organize prompts by subcategory
    prompts_by_subcategory = {}
    for row in query_job.result():
        if row.subcategory not in prompts_by_subcategory:
            prompts_by_subcategory[row.subcategory] = []
        prompts_by_subcategory[row.subcategory].append({
            'prompt': row.prompt,
            'button_name': row.button_name
        })

    return render_template('prompt_menu.html', category=category, prompts_by_subcategory=prompts_by_subcategory)

@app.route('/manage-prompts')
@login_required
def manage_prompts():
    selected_category = request.args.get('category')
    selected_subcategory = request.args.get('subcategory')

    # Fetch categories for the dropdown
    query = f"""
        SELECT DISTINCT category
        FROM `{project_id}.{dataset_id}.{table_id}`
        ORDER BY category
    """
    query_job = bigquery_client.query(query)
    categories = [row.category for row in query_job.result()]

    # Fetch subcategories for the dropdown based on the selected category
    if selected_category:
        subcategory_query = f"""
            SELECT DISTINCT subcategory
            FROM `{project_id}.{dataset_id}.{table_id}`
            WHERE category = @category
            ORDER BY subcategory
        """
        subcategory_job = bigquery_client.query(subcategory_query, job_config=bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("category", "STRING", selected_category)]
        ))
        subcategories = [row.subcategory for row in subcategory_job.result()]
    else:
        # Fetch all distinct subcategories if no category is selected
        subcategory_query = f"""
            SELECT DISTINCT subcategory
            FROM `{project_id}.{dataset_id}.{table_id}`
            ORDER BY subcategory
        """
        subcategory_job = bigquery_client.query(subcategory_query)
        subcategories = [row.subcategory for row in subcategory_job.result()]

    # Construct the WHERE clause dynamically based on user selection
    where_clauses = []
    query_params = []

    if selected_category:
        where_clauses.append("category = @category")
        query_params.append(bigquery.ScalarQueryParameter("category", "STRING", selected_category))

    if selected_subcategory:
        where_clauses.append("subcategory = @subcategory")
        query_params.append(bigquery.ScalarQueryParameter("subcategory", "STRING", selected_subcategory))

    # Construct the final query
    if where_clauses:
        where_clause = " WHERE " + " AND ".join(where_clauses)
    else:
        where_clause = ""

    final_query = f"""
        SELECT id, prompt, category, subcategory, button_name
        FROM `{project_id}.{dataset_id}.{table_id}`
        {where_clause}
        ORDER BY category, subcategory
    """

    query_job = bigquery_client.query(final_query, job_config=bigquery.QueryJobConfig(query_parameters=query_params))
    prompts = query_job.result()

    # Organize prompts by subcategory
    prompts_by_subcategory = {}
    for prompt in prompts:
        if prompt.subcategory not in prompts_by_subcategory:
            prompts_by_subcategory[prompt.subcategory] = []
        prompts_by_subcategory[prompt.subcategory].append({
            'id': prompt.id,
            'prompt': prompt.prompt,
            'category': prompt.category,
            'subcategory': prompt.subcategory,
            'button_name': prompt.button_name
        })

    return render_template('manage_prompts.html', prompts_by_subcategory=prompts_by_subcategory, categories=categories, subcategories=subcategories, selected_category=selected_category, selected_subcategory=selected_subcategory)



@app.route('/submit-prompt', methods=['POST'])
@login_required
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

    # Inserting prompt data into BigQuery without handling instructions here
    rows_to_insert = [
        {
            "id": prompt_id,
            "prompt": sanitized_prompt,
            "category": sanitized_category,
            "subcategory": sanitized_subcategory,
            "button_name": sanitized_button_name,
            "timestamp": datetime.now().isoformat()
        }
    ]

    try:
        errors = bigquery_client.insert_rows_json(f"{dataset_id}.{table_id}", rows_to_insert)
        if errors:
            return f"Encountered errors while inserting rows: {errors}", 500
    except Exception as e:
        return f"An error occurred: {e}", 500

    # Prepare the conversation without adding instructions here
    modified_prompt = f"Here is the prompt, please answer based on the instructions provided: {prompt}"
    conversation = [{"role": "user", "content": modified_prompt}]

    # Call the get_openai_assistant_response function to handle instructions
    response = get_openai_assistant_response(project_id, conversation, openai_client, category=sanitized_category)
    formatted_response = markdown(response)

    # Append the assistant's response to the conversation
    conversation.append({"role": "assistant", "content": formatted_response})

    # Store the conversation in the session
    session['conversation'] = conversation

    # URL-encode the prompt, response, and category to ensure they are safe for use in a URL
    return render_template('results.html', prompt=prompt, response=formatted_response, conversation=conversation)

@app.route('/view-prompt', methods=['GET', 'POST'])
@login_required
def view_prompt():
    if request.method == 'POST':
        # Get the prompt and previous conversation from the form or session
        prompt = request.form['prompt']
        conversation = session.get('conversation', [])
        category = request.form.get('category')  # Assuming category is provided

        file = request.files.get('file')
        if file and file.filename != '':
            file_text = extract_text_from_file(file)
            prompt += "\n\n" + file_text

        # Append the user's prompt (including file content if applicable) to the conversation
        modified_prompt = f"Here is the prompt, please answer based on the instructions provided: {prompt}"
        conversation.append({"role": "user", "content": modified_prompt})

        # Get the response from OpenAI, passing the category for the first interaction
        response = get_openai_assistant_response(project_id, conversation, openai_client, category=category)
        formatted_response = markdown(response)

        # Append the assistant's response to the conversation
        conversation.append({"role": "assistant", "content": formatted_response})

        # Save the conversation to the session
        session['conversation'] = conversation

        return render_template('results.html', prompt=prompt, response=formatted_response, conversation=conversation)

    else:
        # Clear the conversation if this is a GET request to start a new conversation
        session.pop('conversation', None)
        # Render results.html with an empty conversation and no prompt/response
        return render_template('results.html', conversation=[], prompt='', response='')

@app.route('/assign-button-name', methods=['POST'])
@login_required
def assign_button_name():
    prompt_id = request.form['prompt_id']
    button_name = request.form['button_name']

    if not prompt_id or not button_name:
        return "Prompt ID and button name cannot be empty", 400

    # Step 1: Create a new table (temporary or with a new name)
    temp_table_ref = f"{project_id}.{dataset_id}.temp_{table_id}"
    original_table_ref = f"{project_id}.{dataset_id}.{table_id}"

    # Step 2: Copy data to the new table, updating the button name for the selected prompt
    query = f"""
        CREATE OR REPLACE TABLE {temp_table_ref} AS
        SELECT
            id,
            prompt,
            category,
            subcategory,
            instructions,
            CASE WHEN id = @prompt_id THEN @button_name ELSE button_name END as button_name,
            timestamp
        FROM {original_table_ref}
    """
    query_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("prompt_id", "STRING", prompt_id),
            bigquery.ScalarQueryParameter("button_name", "STRING", button_name)
        ]
    )
    bigquery_client.query(query, job_config=query_config).result()

    # Step 3: Replace the original table with the new table
    bigquery_client.delete_table(original_table_ref, not_found_ok=True)
    bigquery_client.query(f"ALTER TABLE {temp_table_ref} RENAME TO {table_id}").result()

    return redirect('/delete-prompts')

@app.route('/delete-prompt', methods=['POST'])
@login_required
def delete_prompt():
    prompt_id = request.form['prompt_id']

    if not prompt_id:
        return "Prompt ID is required", 400

    # Step 1: Create a new table (temporary or with a new name)
    temp_table_ref = f"{project_id}.{dataset_id}.temp_{table_id}"
    original_table_ref = f"{project_id}.{dataset_id}.{table_id}"

    # Step 2: Copy data to the new table, excluding the selected prompt
    query = f"""
        CREATE OR REPLACE TABLE {temp_table_ref} AS
        SELECT
            CASE WHEN id = @prompt_id THEN NULL
            ELSE id
        END AS id,
        prompt,
        category,
        subcategory,
        instructions,
        button_name,
        timestamp
        FROM {original_table_ref}
    """
    query_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("prompt_id", "STRING", prompt_id)
        ]
    )
    try:
        bigquery_client.query(query, job_config=query_config).result()
        print(f"Successfully created temp table excluding the selected prompt.")
    except Exception as e:
        print(f"Error during table creation: {e}")
        return f"An error occurred during prompt deletion: {e}", 500

    # Step 3: Replace the original table with the new table
    try:
        bigquery_client.delete_table(original_table_ref, not_found_ok=True)
        bigquery_client.query(f"ALTER TABLE {temp_table_ref} RENAME TO {table_id}").result()
        print(f"Successfully replaced original table with temp table.")
    except Exception as e:
        print(f"Error during table replacement: {e}")
        return f"An error occurred during table replacement: {e}", 500

    return redirect('/manage-prompts')

@app.route('/edit-prompt', methods=['POST'])
@login_required
def edit_prompt():
    prompt_id = request.form['prompt_id']
    new_prompt_text = request.form['new_prompt_text']

    if not prompt_id or not new_prompt_text:
        return "Prompt ID and new prompt text cannot be empty", 400

    # Debugging: Print the prompt_id and new_prompt_text
    print(f"Editing prompt: {prompt_id} with new text: {new_prompt_text}")

    # Step 1: Create a new table (temporary or with a new name)
    temp_table_ref = f"{project_id}.{dataset_id}.temp_{table_id}"
    original_table_ref = f"{project_id}.{dataset_id}.{table_id}"

    # Step 2: Copy data to the new table, updating the prompt text for the selected prompt
    query = f"""
        CREATE OR REPLACE TABLE {temp_table_ref} AS
        SELECT
            id,
            CASE WHEN id = @prompt_id THEN @new_prompt_text ELSE prompt END as prompt,
            category,
            subcategory,
            instructions,
            button_name,
            timestamp
        FROM {original_table_ref}
    """
    query_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("prompt_id", "STRING", prompt_id),
            bigquery.ScalarQueryParameter("new_prompt_text", "STRING", new_prompt_text)
        ]
    )

    # Debugging: Log the query execution
    print("Executing query to update prompt...")
    bigquery_client.query(query, job_config=query_config).result()

    # Step 3: Replace the original table with the new table
    print(f"Replacing table {original_table_ref} with {temp_table_ref}...")
    bigquery_client.delete_table(original_table_ref, not_found_ok=True)
    bigquery_client.query(f"ALTER TABLE {temp_table_ref} RENAME TO {table_id}").result()

    print("Prompt update successful. Redirecting to delete-prompts...")
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

    # Fetch categories sorted by usage count
    query = f"""
        SELECT DISTINCT category
        FROM `{project_id}.{dataset_id}.{table_id}`
        ORDER BY category
    """
    query_job = bigquery_client.query(query)
    categories = [row.category for row in query_job.result()]

    # Build a new dictionary with categories and their emojis
    categories_with_emojis_filtered = {category: categories_with_emojis.get(category, '') for category in categories}

    return render_template('prompt_categories.html', categories_with_emojis=categories_with_emojis_filtered)

@app.route('/manage-categories')
@login_required
def manage_categories():
    # Fetch distinct categories and their subcategories
    query = f"""
        SELECT DISTINCT category, subcategory
        FROM `{project_id}.{dataset_id}.{table_id}`
        ORDER BY category, subcategory
    """
    query_job = bigquery_client.query(query)
    results = query_job.result()

    categories = {}
    for row in results:
        if row.category not in categories:
            categories[row.category] = []
        if row.subcategory and row.subcategory not in categories[row.category]:
            categories[row.category].append(row.subcategory)

    return render_template('manage_categories.html', categories=categories)

@app.route('/manage-subcategories')
@login_required
def manage_subcategories():
    category = request.args.get('category')

    if not category:
        return redirect('/manage-categories')

    # Fetch subcategories for the specific category
    query = f"""
        SELECT DISTINCT subcategory
        FROM `{project_id}.{dataset_id}.{table_id}`
        WHERE category = @category
        ORDER BY subcategory
    """
    query_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("category", "STRING", category)
        ]
    )
    query_job = bigquery_client.query(query, job_config=query_config)
    subcategories = [row.subcategory for row in query_job.result()]

    return render_template('manage_subcategories.html', category=category, subcategories=subcategories)

@app.route('/add-categories', methods=['POST'])
@login_required
def add_categories():
    categories_input = request.form['categories']  # Expecting a single input string

    if not categories_input:
        return "No categories provided", 400

    # Split the input string by commas and strip any whitespace
    categories = [category.strip() for category in categories_input.split(',')]

    # Sanitize and prepare the categories
    sanitized_categories = [sanitize_text(category, proper=True) for category in categories]

    # Prepare the data to be loaded
    rows_to_insert = [
        {
            "id": str(uuid.uuid4()),
            "prompt": None,
            "category": category,
            "subcategory": None,
            "button_name": None,
            "timestamp": datetime.now().isoformat()
        }
        for category in sanitized_categories
    ]

    # Write the data to a JSON file
    json_filename = "/tmp/categories_to_insert.json"
    try:
        with open(json_filename, 'w') as json_file:
            for row in rows_to_insert:
                json.dump(row, json_file)
                json_file.write('\n')  # Write each JSON object on a new line (NDJSON format)

        # Define the BigQuery table
        table_id = "les-socialites-chat-gpt.prompt_manager.prompts"

        # Load the JSON file into BigQuery
        job_config = bigquery.LoadJobConfig(
            source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
            schema=[
                bigquery.SchemaField("id", "STRING"),
                bigquery.SchemaField("prompt", "STRING"),
                bigquery.SchemaField("category", "STRING"),
                bigquery.SchemaField("subcategory", "STRING"),
                bigquery.SchemaField("button_name", "STRING"),
                bigquery.SchemaField("timestamp", "TIMESTAMP"),
            ],
        )

        with open(json_filename, "rb") as source_file:
            load_job = bigquery_client.load_table_from_file(source_file, table_id, job_config=job_config)

        load_job.result()  # Wait for the job to complete

        if load_job.errors:
            return f"Encountered errors while loading data: {load_job.errors}", 500
    finally:
        # Delete the temporary JSON file after the load is complete
        if os.path.exists(json_filename):
            os.remove(json_filename)

    return redirect('/manage-categories')

@app.route('/add-subcategories', methods=['POST'])
@login_required
def add_subcategories():
    category = request.form['category']
    subcategories_input = request.form['subcategories']  # Expecting a single input string

    if not category or not subcategories_input:
        return "Category and subcategories cannot be empty", 400

    # Split the input string by commas and strip any whitespace
    subcategories = [subcategory.strip() for subcategory in subcategories_input.split(',')]

    # Sanitize and prepare the subcategories
    sanitized_subcategories = [sanitize_text(subcategory, proper=True) for subcategory in subcategories]

    # Prepare the data to be loaded
    rows_to_insert = [
        {
            "id": str(uuid.uuid4()),
            "prompt": None,
            "category": category,
            "subcategory": subcategory,
            "button_name": None,
            "timestamp": datetime.now().isoformat()
        }
        for subcategory in sanitized_subcategories
    ]

    # Write the data to a JSON file
    json_filename = "/tmp/subcategories_to_insert.json"
    try:
        with open(json_filename, 'w') as json_file:
            for row in rows_to_insert:
                json.dump(row, json_file)
                json_file.write('\n')  # Write each JSON object on a new line (NDJSON format)

        # Define the BigQuery table
        table_id = "les-socialites-chat-gpt.prompt_manager.prompts"

        # Load the JSON file into BigQuery
        job_config = bigquery.LoadJobConfig(
            source_format=bigquery.SourceFormat.NEWLINE_DELIMITED_JSON,
            schema=[
                bigquery.SchemaField("id", "STRING"),
                bigquery.SchemaField("prompt", "STRING"),
                bigquery.SchemaField("category", "STRING"),
                bigquery.SchemaField("subcategory", "STRING"),
                bigquery.SchemaField("button_name", "STRING"),
                bigquery.SchemaField("timestamp", "TIMESTAMP"),
            ],
        )

        with open(json_filename, "rb") as source_file:
            load_job = bigquery_client.load_table_from_file(source_file, table_id, job_config=job_config)

        load_job.result()  # Wait for the job to complete

        if load_job.errors:
            return f"Encountered errors while loading data: {load_job.errors}", 500

    finally:
        # Delete the temporary JSON file after the load is complete
        if os.path.exists(json_filename):
            os.remove(json_filename)

    return redirect('/manage-categories')

@app.route('/edit-category', methods=['POST'])
@login_required
def edit_category():
    old_category = request.form['old_category']
    new_category_name = request.form['new_category_name']

    if not old_category or not new_category_name:
        return "Category names cannot be empty", 400

    # Sanitize the new category name for proper capitalization
    new_category_name = sanitize_text(new_category_name, proper=True)

    # Step 1: Create a new table (temporary or with a new name)
    temp_table_ref = f"{project_id}.{dataset_id}.temp_{table_id}"
    original_table_ref = f"{project_id}.{dataset_id}.{table_id}"

    # Step 2: Copy data to the new table, updating the category name
    query = f"""
        CREATE OR REPLACE TABLE {temp_table_ref} AS
        SELECT
            id,
            prompt,
            CASE WHEN category = @old_category THEN @new_category_name ELSE category END as category,
            subcategory,
            instructions,
            button_name,
            timestamp
        FROM {original_table_ref}
    """
    query_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("old_category", "STRING", old_category),
            bigquery.ScalarQueryParameter("new_category_name", "STRING", new_category_name)
        ]
    )
    bigquery_client.query(query, job_config=query_config).result()

    # Step 3: Replace the original table with the new table
    bigquery_client.delete_table(original_table_ref, not_found_ok=True)
    bigquery_client.query(f"ALTER TABLE {temp_table_ref} RENAME TO {table_id}").result()

    return redirect('/manage-categories')

@app.route('/edit-subcategory', methods=['POST'])
@login_required
def edit_subcategory():
    category = request.form['category']
    old_subcategory = request.form['old_subcategory']
    new_subcategory_name = request.form['new_subcategory_name']

    if not category or not old_subcategory or not new_subcategory_name:
        return "Category, old subcategory, and new subcategory names cannot be empty", 400

    # Sanitize the new category name for proper capitalization
    new_subcategory_name = sanitize_text(new_subcategory_name, proper=True)

    # Step 1: Create a new table (temporary or with a new name)
    temp_table_ref = f"{project_id}.{dataset_id}.temp_{table_id}"
    original_table_ref = f"{project_id}.{dataset_id}.{table_id}"

    # Step 2: Copy data to the new table, updating the subcategory name
    query = f"""
        CREATE OR REPLACE TABLE {temp_table_ref} AS
        SELECT
            id,
            prompt,
            category,
            CASE
                WHEN category = @category AND subcategory = @old_subcategory
                    THEN @new_subcategory_name
                ELSE subcategory
            END as subcategory,
            instructions,
            button_name,
            timestamp
        FROM {original_table_ref}
    """
    query_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("category", "STRING", category),
            bigquery.ScalarQueryParameter("old_subcategory", "STRING", old_subcategory),
            bigquery.ScalarQueryParameter("new_subcategory_name", "STRING", new_subcategory_name)
        ]
    )
    bigquery_client.query(query, job_config=query_config).result()

    # Step 3: Replace the original table with the new table
    bigquery_client.delete_table(original_table_ref, not_found_ok=True)
    bigquery_client.query(f"ALTER TABLE {temp_table_ref} RENAME TO {table_id}").result()

    return redirect('/manage-categories')

@app.route('/delete-category', methods=['POST'])
@login_required
def delete_category():
    category = request.form['category']

    if not category:
        return "Category name cannot be empty", 400

    # Step 1: Create a new table (temporary or with a new name)
    temp_table_ref = f"{project_id}.{dataset_id}.temp_{table_id}"
    original_table_ref = f"{project_id}.{dataset_id}.{table_id}"

    # Step 2: Copy data to the new table, excluding the selected category
    query = f"""
        CREATE OR REPLACE TABLE {temp_table_ref} AS
        SELECT
            id,
            prompt,
            CASE
                WHEN category = @category THEN NULL
                ELSE category
            END AS category,
            subcategory,
            instructions,
            button_name,
            timestamp
        FROM {original_table_ref}
    """
    query_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("category", "STRING", category)
        ]
    )
    bigquery_client.query(query, job_config=query_config).result()

    # Step 3: Replace the original table with the new table
    bigquery_client.delete_table(original_table_ref, not_found_ok=True)
    bigquery_client.query(f"ALTER TABLE {temp_table_ref} RENAME TO {table_id}").result()

    return redirect('/manage-categories')

@app.route('/delete-subcategory', methods=['POST'])
@login_required
def delete_subcategory():
    category = request.form['category']
    subcategory = request.form['subcategory']

    if not category or not subcategory:
        return "Category and subcategory names cannot be empty", 400

    # Step 1: Create a new table (temporary or with a new name) with updated data
    temp_table_ref = f"{project_id}.{dataset_id}.temp_{table_id}"
    original_table_ref = f"{project_id}.{dataset_id}.{table_id}"

    # Step 2: Copy data to the new table, setting the subcategory to NULL where it matches the category and subcategory
    query = f"""
        CREATE OR REPLACE TABLE {temp_table_ref} AS
        SELECT
            id,
            prompt,
            category,
            CASE
                WHEN category = @category AND subcategory = @subcategory THEN NULL
                ELSE subcategory
            END AS subcategory,
            instructions,
            button_name,
            timestamp
        FROM {original_table_ref}
    """
    query_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("category", "STRING", category),
            bigquery.ScalarQueryParameter("subcategory", "STRING", subcategory)
        ]
    )
    bigquery_client.query(query, job_config=query_config).result()

    # Step 3: Replace the original table with the new table
    bigquery_client.delete_table(original_table_ref, not_found_ok=True)
    bigquery_client.query(f"ALTER TABLE {temp_table_ref} RENAME TO {table_id}").result()

    return redirect('/manage-categories')



### ROUTES FOR INSTRUCTIONS ###

@app.route('/update-instructions', methods=['POST'])
@login_required
def update_instructions():
    category = request.form['category']
    new_instructions = request.form['instructions']

    if not category or not new_instructions:
        return "Category and Instructions cannot be empty", 400

    # Step 1: Create a new table (temporary or with a new name)
    temp_table_ref = f"{project_id}.{dataset_id}.temp_{table_id}"
    original_table_ref = f"{project_id}.{dataset_id}.{table_id}"

    # Step 2: Copy data to the new table, updating the instructions for the selected category
    query = f"""
        CREATE OR REPLACE TABLE {temp_table_ref} AS
        SELECT
            id,
            prompt,
            category,
            subcategory,
            CASE
                WHEN category = @category
                    THEN @new_instructions
                ELSE instructions
            END AS instructions,
            button_name,
            timestamp
        FROM {original_table_ref}
    """
    query_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("category", "STRING", category),
            bigquery.ScalarQueryParameter("new_instructions", "STRING", new_instructions)
        ]
    )
    bigquery_client.query(query, job_config=query_config).result()

    # Step 3: Replace the original table with the new table
    bigquery_client.delete_table(original_table_ref, not_found_ok=True)
    bigquery_client.query(f"ALTER TABLE {temp_table_ref} RENAME TO {table_id}").result()

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

### ROUTES FOR LOGIN ###

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
        "wyzard.feedback@gmail.com"
    ]

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check if the email is in the whitelist
        if email not in whitelisted_emails:
            flash("Your email is not authorized to register.", "error")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

        # Check if the user already exists
        check_query = f"""
            SELECT id
            FROM `{project_id}.{dataset_id}.users`
            WHERE email = @email
            LIMIT 1
        """
        query_job = bigquery_client.query(check_query, job_config=bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("email", "STRING", email)]
        ))
        result = query_job.result()

        if list(result):
            flash("Email already exists.", "error")
            return redirect(url_for('register'))

        # Insert new user into BigQuery
        user_id = str(uuid.uuid4())
        rows_to_insert = [
            {
                "id": user_id,
                "email": email,
                "password": hashed_password,
                "timestamp": datetime.now().isoformat()
            }
        ]
        bigquery_client.insert_rows_json(f"{dataset_id}.users", rows_to_insert)

        # Flash success message with a 'success' category
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Query BigQuery for the user
        query = f"""
            SELECT id, email, password
            FROM `{project_id}.{dataset_id}.users`
            WHERE email = @email
            LIMIT 1
        """
        query_job = bigquery_client.query(query, job_config=bigquery.QueryJobConfig(
            query_parameters=[bigquery.ScalarQueryParameter("email", "STRING", email)]
        ))
        result = query_job.result()

        if not result:
            flash("Email or password is incorrect.")
            return redirect(url_for('login'))

        row = list(result)[0]
        user = User(user_id=row.id, email=row.email, password=row.password)

        if check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('results'))
        else:
            flash("Email or password is incorrect.")
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


### ROUTES FOR KNOWLEDGE BASE ###

@app.route('/knowledge-base')
def knowledge_base():
    # Fetch knowledge instructions from BigQuery
    query = f"""
        SELECT id, knowledge_instructions
        FROM `{project_id}.{dataset_id}.knowledge_base`
        WHERE business_id = @business_id
        ORDER BY timestamp DESC
    """
    query_config = bigquery.QueryJobConfig(
        query_parameters=[bigquery.ScalarQueryParameter("business_id", "STRING", sanitize_project(project_id))]
    )
    query_job = bigquery_client.query(query, job_config=query_config)
    knowledge_instructions = [
        {"id": row.id, "knowledge_instructions": row.knowledge_instructions}
        for row in query_job.result()
    ]

    return render_template('knowledge_base.html', knowledge_instructions=knowledge_instructions)

@app.route('/submit-knowledge', methods=['POST'])
def submit_knowledge():
    knowledge_instructions = request.form['knowledge_instructions']

    # Insert into BigQuery
    rows_to_insert = [
        {
            "id": str(uuid.uuid4()),
            "business_id": sanitize_project(project_id),
            "knowledge_instructions": sanitize_text(knowledge_instructions),
            "timestamp": datetime.now().isoformat()
        }
    ]
    bigquery_client.insert_rows_json(f"{dataset_id}.knowledge_base", rows_to_insert)

    return redirect(url_for('knowledge_base'))

@app.route('/delete-knowledge', methods=['POST'])
def delete_knowledge():
    instruction_id = request.form['id']

    # Step 1: Create a new table excluding the deleted instruction
    temp_table_ref = f"{project_id}.{dataset_id}.temp_knowledge_base"
    original_table_ref = f"{project_id}.{dataset_id}.knowledge_base"

    query = f"""
        CREATE OR REPLACE TABLE {temp_table_ref} AS
        SELECT * EXCEPT (id)
        FROM {original_table_ref}
        WHERE id != @id
    """
    query_config = bigquery.QueryJobConfig(
        query_parameters=[bigquery.ScalarQueryParameter("id", "STRING", instruction_id)]
    )
    bigquery_client.query(query, job_config=query_config).result()

    # Step 2: Replace the original table with the updated table
    bigquery_client.delete_table(original_table_ref, not_found_ok=True)
    bigquery_client.query(f"ALTER TABLE {temp_table_ref} RENAME TO knowledge_base").result()

    return redirect(url_for('knowledge_base'))


if __name__ == '__main__':
    app.run(debug=True, port=5001)
