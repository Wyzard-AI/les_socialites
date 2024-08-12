import json
import re
from flask import Flask, request, redirect, render_template
from google.cloud import bigquery, secretmanager
from google.oauth2 import service_account
from datetime import datetime
import uuid
from openai import OpenAI

def get_secret(secret_name):
    secret_client = secretmanager.SecretManagerServiceClient()
    secret_resource_name = f"projects/916481347801/secrets/{secret_name}/versions/1"
    response = secret_client.access_secret_version(name=secret_resource_name)
    secret_payload = response.payload.data.decode('UTF-8')
    return secret_payload

def fetch_prompts_from_bigquery(project_id, dataset_id, table_id, include_deleted=False, category=None):
    table_ref = f"`{project_id}.{dataset_id}.{table_id}`"

    if include_deleted:
        query = f"""
            SELECT id, prompt, category, button_name
            FROM {table_ref}
        """
    else:
        query = f"""
            SELECT id, prompt, category, button_name
            FROM {table_ref}
            WHERE is_deleted = FALSE
        """

    if category:
        query += " AND category = @category"
        query_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ScalarQueryParameter("category", "STRING", category)
            ]
        )
    else:
        query_config = None  # Ensure query_config is None if no category

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
            "button_name": row.button_name
        })

    return prompts

def sanitize_text(text):
    text = text.replace('\n', ' ').replace('\r', ' ')
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def get_openai_assistant_response(prompt, openai_client, category=None):
    # Default instructions
    default_instructions = """
        You are a manager at an influencer marketing company that does business in Canada and the United States.
    """

    if category:
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
    else:
        instructions = default_instructions

    # Sanitize the inputs
    sanitized_prompt = sanitize_text(prompt)
    sanitized_instructions = sanitize_text(instructions)

    # Prepare the messages
    messages = [
        {"role": "system", "content": sanitized_instructions},
        {"role": "user", "content": sanitized_prompt}
    ]

    # Call the OpenAI API
    try:
        response = openai_client.chat.completions.create(
            model="gpt-4o",
            messages=messages
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"An error occurred: {e}"

app = Flask(__name__)

project_id = 'les-socialites-chat-gpt'
dataset_id = 'prompt_manager'
table_id = 'prompts'

bigquery_service_key = get_secret('les-socialites-bigquery-service-account-key')
service_account_info = json.loads(bigquery_service_key)
credentials = service_account.Credentials.from_service_account_info(service_account_info)
bigquery_client = bigquery.Client(credentials=credentials, project=service_account_info['project_id'])

openai_api_key = get_secret('les-socialites-openai-access-token')
openai_client = OpenAI(api_key=openai_api_key)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit-prompt', methods=['POST'])
def submit_prompt():
    prompt = request.form['prompt']
    category = request.form['category']

    if not prompt:
        return "Prompt cannot be empty", 400
    if not category:
        return "Category cannot be empty", 400

    sanitized_prompt = sanitize_text(prompt)
    sanitized_category = sanitize_text(category)
    prompt_id = str(uuid.uuid4())

    # Check for existing instructions in the same category
    query = f"""
        SELECT instructions
        FROM `{project_id}.{dataset_id}.{table_id}`
        WHERE category = @category
        LIMIT 1
    """
    query_config = bigquery.QueryJobConfig(
        query_parameters=[
            bigquery.ScalarQueryParameter("category", "STRING", sanitized_category)
        ]
    )
    query_job = bigquery_client.query(query, job_config=query_config)
    result = query_job.result()

    # Set instructions to the matching category's instructions if found, otherwise set to None
    instructions = None
    for row in result:
        instructions = row.instructions
        break  # Only take the first matching instruction

    rows_to_insert = [
        {
            "id": prompt_id,
            "prompt": sanitized_prompt,
            "category": sanitized_category,
            "instructions": instructions,
            "button_name": None,
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

    response = get_openai_assistant_response(sanitized_prompt, openai_client)
    sanitized_response = sanitize_text(response)

    return redirect(f'/thank-you?prompt={sanitized_prompt}&response={sanitized_response}&category={sanitized_category}')

@app.route('/thank-you')
def thank_you():
    prompt = request.args.get('prompt')
    response = request.args.get('response')
    return render_template('thank_you.html', prompt=prompt, response=response)

@app.route('/prompt-menu')
def prompt_menu():
    category = request.args.get('category')
    prompts = fetch_prompts_from_bigquery(project_id, dataset_id, table_id, category=category)
    return render_template('prompt_menu.html', prompts=prompts)

@app.route('/prompt-categories')
def prompt_categories():
    query = f"""
        SELECT DISTINCT category
        FROM `{project_id}.{dataset_id}.{table_id}`
        WHERE is_deleted = FALSE
    """
    query_job = bigquery_client.query(query)
    results = query_job.result()

    categories = [row.category for row in results]

    return render_template('prompt_categories.html', categories=categories)

@app.route('/results')
def results():
    prompt = request.args.get('prompt')
    response = request.args.get('response')
    return render_template('results.html', prompt=prompt, response=response)

@app.route('/view-prompt')
def view_prompt():
    prompt = request.args.get('prompt')
    response = get_openai_assistant_response(prompt, openai_client)
    return render_template('results.html', prompt=prompt, response=response)

@app.route('/delete-prompts')
def delete_prompts():
    prompts = fetch_prompts_from_bigquery(project_id, dataset_id, table_id)
    return render_template('delete_prompts.html', prompts=prompts)

@app.route('/manage-prompts')
def manage_prompts():
    prompts = fetch_prompts_from_bigquery(project_id, dataset_id, table_id)
    return render_template('manage_prompts.html', prompts=prompts)


@app.route('/remove-selected-prompts', methods=['POST'])
def remove_selected_prompts():
    selected_prompt_ids = request.form.getlist('selected_prompts')

    if selected_prompt_ids:
        # Debug: Log selected IDs
        print(f"Selected prompt IDs for deletion: {selected_prompt_ids}")

        # Step 1: Create a new table (temporary or with a new name)
        temp_table_ref = f"{project_id}.{dataset_id}.temp_{table_id}"
        original_table_ref = f"{project_id}.{dataset_id}.{table_id}"

        # Step 2: Copy data to the new table, excluding selected prompts
        query = f"""
            CREATE OR REPLACE TABLE {temp_table_ref} AS
            SELECT *
            FROM {original_table_ref}
            WHERE id NOT IN UNNEST(@selected_ids)
        """
        query_config = bigquery.QueryJobConfig(
            query_parameters=[
                bigquery.ArrayQueryParameter("selected_ids", "STRING", selected_prompt_ids)
            ]
        )
        try:
            bigquery_client.query(query, job_config=query_config).result()
            # Debug: Log success of query
            print(f"Successfully created temp table excluding selected prompts.")
        except Exception as e:
            print(f"Error during table creation: {e}")
            return f"An error occurred during prompt deletion: {e}", 500

        # Step 3: Replace the original table with the new table
        try:
            bigquery_client.delete_table(original_table_ref, not_found_ok=True)
            bigquery_client.query(f"ALTER TABLE {temp_table_ref} RENAME TO {table_id}").result()
            # Debug: Log success of table replacement
            print(f"Successfully replaced original table with temp table.")
        except Exception as e:
            print(f"Error during table replacement: {e}")
            return f"An error occurred during table replacement: {e}", 500

    return redirect('/prompt-menu')

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
    return redirect('/delete-prompts')

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

    return redirect('/prompt-categories')

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

if __name__ == '__main__':
    app.run(debug=True)
