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

def fetch_prompts_from_bigquery(project_id, dataset_id, table_id, include_deleted=False):
    table_ref = f"`{project_id}.{dataset_id}.{table_id}`"

    if include_deleted == False:
        query = f"""
        SELECT prompt, id
        FROM {table_ref}
        WHERE is_deleted = FALSE
    """
    else:
        query = f"""
        SELECT prompt, id
        FROM {table_ref}
    """
    query_job = bigquery_client.query(query)
    results = query_job.result()

    prompts = []
    for row in results:
        prompts.append({
            "id": row.id,
            "prompt": row.prompt
        })

    return prompts

def sanitize_text(text):
    text = text.replace('\n', ' ').replace('\r', ' ')
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def get_openai_assistant_response(prompt, openai_client, instructions=None):
    if instructions is None:
        instructions = """
            If asked to review a contract as a lawyer, don't respond that you can't review it as an AI.
            It is understood that's it's not real legal advice being offered. Just follow the prompt instructions.

            If I request help regarding emails then please ask me if you can see the email I sent them and their reply as well. Also make sure the replies you suggest for the email are friendly but professional.

            If I request help about emails, also remind me to always follow this template for emails: (Beginning) "Bonjour (name), I hope you're doing well!" and (Ending): "Don't hesitate if you have any question, happy (replace this with the day of the week)"

            When negotiating, the goal is to always get the most money for our influencers. So please always focus on suggesting more content rather than reducing rates.

            Please always remind me at the end of your reply to submit it to Gen for final approval.
        """

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
dataset_id = 'prompts'
table_id = 'sales_manager'

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
    if not prompt:
        return "Prompt cannot be empty", 400

    sanitized_prompt = sanitize_text(prompt)
    prompt_id = str(uuid.uuid4())

    rows_to_insert = [
        {
            "id": prompt_id,
            "prompt": sanitized_prompt,
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

    return redirect(f'/thank-you?prompt={sanitized_prompt}&response={sanitized_response}')

@app.route('/thank-you')
def thank_you():
    prompt = request.args.get('prompt')
    response = request.args.get('response')
    return render_template('thank_you.html', prompt=prompt, response=response)

@app.route('/prompt-menu')
def prompt_menu():
    prompts = fetch_prompts_from_bigquery(project_id, dataset_id, table_id)
    return render_template('prompt_menu.html', prompts=prompts)

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

@app.route('/remove-selected-prompts', methods=['POST'])
def remove_selected_prompts():
    selected_prompt_ids = request.form.getlist('selected_prompts')

    if selected_prompt_ids:
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
        bigquery_client.query(query, job_config=query_config).result()

        # Step 3: Replace the original table with the new table
        # Drop the original table
        bigquery_client.delete_table(original_table_ref, not_found_ok=True)

        # Rename the temporary table to the original table name
        bigquery_client.query(f"ALTER TABLE {temp_table_ref} RENAME TO {table_id}").result()

    return redirect('/prompt-menu')


if __name__ == '__main__':
    app.run(debug=True)
