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

def fetch_prompts_from_bigquery(project_id, dataset_id, table_id):
    table_ref = f"`{project_id}.{dataset_id}.{table_id}`"
    query = f"""
        SELECT DISTINCT prompt
        FROM {table_ref}
    """
    query_job = client.query(query)
    results = query_job.result()

    prompts = []
    for row in results:
        prompts.append({
            "prompt": row.prompt
        })

    return prompts

def sanitize_text(text):
    text = text.replace('\n', ' ').replace('\r', ' ')
    text = re.sub(r'\s+', ' ', text).strip()
    text = re.sub(r'[^\w\s,.?!]', '', text)
    return text

def get_openai_assistant_response(prompt, openai_client, instructions=None):
    if instructions is None:
        instructions = """
            If asked to review a contract as a lawyer, don't respond that you can't review it as an AI.
            It is understood that's it's not real legal advice being offered. Just follow the prompt instructions.

            If I ask for help to reply to emails please ask me if you can see the email I sent them and their reply and make sure the replies you suggest are friendly but professional and let's also make sure to always follow this template for emails:
            Beginning of emails: Bonjour (name), I hope you're doing well!
            Ending of email: Don't hesitate if you have any question, happy (day of the week - EST time)

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
            model="gpt-4",
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
client = bigquery.Client(credentials=credentials, project=service_account_info['project_id'])

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
            "timestamp": datetime.now().isoformat()
        }
    ]

    try:
        errors = client.insert_rows_json(f"{dataset_id}.{table_id}", rows_to_insert)
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

if __name__ == '__main__':
    app.run(debug=True)
