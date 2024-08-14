### IMPORTS START ###
import os
import json
import re
import uuid
from pypdf import PdfReader
from flask import Flask, request, redirect, render_template, session
from google.cloud import bigquery, secretmanager
from google.oauth2 import service_account
from datetime import datetime, timedelta
from openai import OpenAI
from werkzeug.utils import secure_filename
from docx import Document
from markdown2 import markdown
from flask_session import Session


### FUNCTIONS START ###
def get_secret(secret_name):
    secret_client = secretmanager.SecretManagerServiceClient()
    secret_resource_name = f"projects/916481347801/secrets/{secret_name}/versions/1"
    response = secret_client.access_secret_version(name=secret_resource_name)
    secret_payload = response.payload.data.decode('UTF-8')
    return secret_payload

def fetch_prompts_from_bigquery(project_id, dataset_id, table_id, include_deleted=False, category=None, subcategory=None):
    table_ref = f"`{project_id}.{dataset_id}.{table_id}`"

    if include_deleted:
        query = f"""
            SELECT id, prompt, category, subcategory, button_name
            FROM {table_ref}
            WHERE 1=1
        """
    else:
        query = f"""
            SELECT id, prompt, category, subcategory, button_name
            FROM {table_ref}
            WHERE is_deleted = FALSE
        """

    query_params = []
    if category:
        query += " AND category = @category"
        query_params.append(bigquery.ScalarQueryParameter("category", "STRING", category))

    if subcategory:
        query += " AND subcategory = @subcategory"
        query_params.append(bigquery.ScalarQueryParameter("subcategory", "STRING", subcategory))

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

def get_openai_assistant_response(conversation, openai_client, category=None):
    # Check if the conversation is just starting
    if category:
        # Default instructions
        default_instructions = """
            You are a manager at an influencer marketing company that does business in Canada and the United States.
        """

        # Fetch instructions from BigQuery based on the category
        query = f"""
            SELECT instructions
            FROM `{project_id}.{dataset_id}.{table_id}`
            WHERE category = @category
            LIMIT 1
        """
        query_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("category", "STRING", category)
            ]
        )
        query_job = bigquery_client.query(query, job_config=query_config)
        result = query_job.result()

        instructions = None
        for row in result:
            instructions = row.instructions

        if not instructions:
            instructions = default_instructions

        # Sanitize the instructions and add them to the conversation
        sanitized_instructions = sanitize_text(instructions)
        conversation.append({"role": "system", "content": sanitized_instructions})

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


### APP START ###
app = Flask(__name__)

app.secret_key = get_secret('les-socialites-app-secret-key')

# Configure server-side session storage
app.config["SESSION_TYPE"] = "filesystem"  # You can also use "redis", "memcached", etc.
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_FILE_DIR"] = os.path.join(os.getcwd(), 'flask_session_files')
app.config["SESSION_USE_SIGNER"] = True  # Encrypt the session cookie
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=10)

# Initialize the session
Session(app)

project_id = 'les-socialites-chat-gpt'
dataset_id = 'prompt_manager'
table_id = 'prompts'

bigquery_service_key = get_secret('les-socialites-bigquery-service-account-key')
service_account_info = json.loads(bigquery_service_key)
credentials = service_account.Credentials.from_service_account_info(service_account_info)
bigquery_client = bigquery.Client(credentials=credentials, project=service_account_info['project_id'])

openai_api_key = get_secret('les-socialites-openai-access-token')
openai_client = OpenAI(api_key=openai_api_key)

@app.before_request
def make_session_permanent():
    session.permanent = True

@app.route('/')
def index():
    # Fetch categories from BigQuery
    query = f"""
        SELECT DISTINCT category
        FROM `{project_id}.{dataset_id}.{table_id}`
        WHERE is_deleted = FALSE
    """
    query_job = bigquery_client.query(query)
    categories = [row.category for row in query_job.result()]

    return render_template('index.html', categories=categories)

@app.route('/thank-you')
def thank_you():
    prompt = request.args.get('prompt')
    response = request.args.get('response')
    return render_template('thank_you.html', prompt=prompt, response=response)

@app.route('/results')
def results():
    # Retrieve the conversation from the session
    conversation = session.get('conversation', [])

    return render_template('results.html', conversation=conversation)

@app.route('/start-new-conversation')
def start_new_conversation():
    # Clear the session data to start a new conversation
    session.pop('conversation', None)
    return redirect('/view-prompt')

### ROUTES FOR PROMPTS ###

@app.route('/prompt-menu')
def prompt_menu():
    category = request.args.get('category')
    subcategory = request.args.get('subcategory')

    # Fetch distinct subcategories based on the selected category
    query = f"""
        SELECT DISTINCT subcategory
        FROM `{project_id}.{dataset_id}.{table_id}`
        WHERE is_deleted = FALSE AND category = @category AND subcategory IS NOT NULL
    """
    query_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("category", "STRING", category)
        ]
    )
    query_job = bigquery_client.query(query, job_config=query_config)
    subcategories = [row.subcategory for row in query_job.result()]

    prompts = fetch_prompts_from_bigquery(project_id, dataset_id, table_id, category=category, subcategory=subcategory)

    return render_template('prompt_menu.html', prompts=prompts, subcategories=subcategories)


@app.route('/manage-prompts')
def manage_prompts():
    selected_category = request.args.get('category')

    # Fetch categories for the dropdown
    query = f"""
        SELECT DISTINCT category
        FROM `{project_id}.{dataset_id}.{table_id}`
        WHERE is_deleted = FALSE
    """
    query_job = bigquery_client.query(query)
    categories = [row.category for row in query_job.result()]

    # Fetch prompts, optionally filtering by the selected category
    if selected_category:
        prompts = fetch_prompts_from_bigquery(project_id, dataset_id, table_id, category=selected_category)
    else:
        prompts = fetch_prompts_from_bigquery(project_id, dataset_id, table_id)

    return render_template('manage_prompts.html', prompts=prompts, categories=categories, selected_category=selected_category)

@app.route('/submit-prompt', methods=['POST'])
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
            "timestamp": datetime.now().isoformat(),
            "is_deleted": False
        }
    ]

    try:
        errors = bigquery_client.insert_rows_json(f"{dataset_id}.{table_id}", rows_to_insert)
        if errors:
            return f"Encountered errors while inserting rows: {errors}", 500
    except Exception as e:
        return f"An error occurred: {e}", 500

    # Prepare the conversation without adding instructions here
    conversation = [{"role": "user", "content": sanitized_prompt}]

    # Call the get_openai_assistant_response function to handle instructions
    response = get_openai_assistant_response(conversation, openai_client, category=sanitized_category)
    formatted_response = markdown(response)

    # Append the assistant's response to the conversation
    conversation.append({"role": "assistant", "content": formatted_response})

    # Store the conversation in the session
    session['conversation'] = conversation

    return redirect(f'/thank-you?prompt={sanitized_prompt}&response={formatted_response}&category={sanitized_category}')

@app.route('/view-prompt', methods=['GET', 'POST'])
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
        conversation.append({"role": "user", "content": prompt})

        # Get the response from OpenAI, passing the category for the first interaction
        response = get_openai_assistant_response(conversation, openai_client, category=category)
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
            timestamp,
            is_deleted
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
        SELECT *
        FROM {original_table_ref}
        WHERE id != @prompt_id
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
            timestamp,
            is_deleted
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
def prompt_categories():
    # Fetch categories sorted by usage count
    query = f"""
        SELECT category, COUNT(*) as usage_count
        FROM `{project_id}.{dataset_id}.{table_id}`
        WHERE is_deleted = FALSE
        GROUP BY category
        ORDER BY usage_count DESC
    """
    query_job = bigquery_client.query(query)
    categories = [row.category for row in query_job.result()]

    return render_template('prompt_categories.html', categories=categories)

@app.route('/manage-categories')
def manage_categories():
    # Fetch distinct categories and their subcategories
    query = f"""
        SELECT DISTINCT category, subcategory
        FROM `{project_id}.{dataset_id}.{table_id}`
        WHERE is_deleted = FALSE
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
def manage_subcategories():
    category = request.args.get('category')

    if not category:
        return redirect('/manage-categories')

    # Fetch subcategories for the specific category
    query = f"""
        SELECT DISTINCT subcategory
        FROM `{project_id}.{dataset_id}.{table_id}`
        WHERE category = @category AND is_deleted = FALSE
    """
    query_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("category", "STRING", category)
        ]
    )
    query_job = bigquery_client.query(query, job_config=query_config)
    subcategories = [row.subcategory for row in query_job.result()]

    return render_template('manage_subcategories.html', category=category, subcategories=subcategories)

@app.route('/edit-category', methods=['POST'])
def edit_category():
    old_category = request.form['old_category']
    new_category_name = request.form['new_category_name']

    if not old_category or not new_category_name:
        return "Category names cannot be empty", 400

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
            timestamp,
            is_deleted
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
def edit_subcategory():
    category = request.form['category']
    old_subcategory = request.form['old_subcategory']
    new_subcategory_name = request.form['new_subcategory_name']

    if not category or not old_subcategory or not new_subcategory_name:
        return "Category, old subcategory, and new subcategory names cannot be empty", 400

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
            CASE WHEN category = @category AND subcategory = @old_subcategory THEN @new_subcategory_name ELSE subcategory END as subcategory,
            instructions,
            button_name,
            timestamp,
            is_deleted
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
        SELECT *
        FROM {original_table_ref}
        WHERE category != @category
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
def delete_subcategory():
    category = request.form['category']
    subcategory = request.form['subcategory']

    if not category or not subcategory:
        return "Category and subcategory names cannot be empty", 400

    # Step 1: Create a new table (temporary or with a new name)
    temp_table_ref = f"{project_id}.{dataset_id}.temp_{table_id}"
    original_table_ref = f"{project_id}.{dataset_id}.{table_id}"

    # Step 2: Copy data to the new table, excluding the selected subcategory
    query = f"""
        CREATE OR REPLACE TABLE {temp_table_ref} AS
        SELECT *
        FROM {original_table_ref}
        WHERE NOT (category = @category AND subcategory = @subcategory)
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
            CASE WHEN category = @category THEN @new_instructions ELSE instructions END as instructions,
            button_name,
            timestamp,
            is_deleted
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

if __name__ == '__main__':
    app.run(debug=True, port=5000)
