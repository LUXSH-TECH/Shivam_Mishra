# app.py
from flask import Flask, render_template, request, jsonify, redirect, url_for
import requests
import json
from flask_cors import CORS # Import CORS

# --- Configuration ---
# Replace with the actual URL where your Django API is running
DJANGO_API_BASE_URL = 'http://127.0.0.1:8001/api' # Ensure this matches your Django server port

# List of websites you plan to support (matching Website.name in Django)
WEBSITES = ["MHRA Products", "BNF", "emc"]

app = Flask(__name__)
CORS(app) # Enable CORS for all routes - essential for Django communication
# app.config['SECRET_KEY'] = 'your_secret_key_here' # Needed for session management if you add it later

# --- Routes ---

@app.route('/', methods=['GET', 'POST'])
def index():
    """
    Handles the main page load (GET) and search submission (POST).
    Also handles displaying derived products after feedback.
    """
    search_query_text = ""
    search_id = None
    search_results = {site: [] for site in WEBSITES}
    error_message = None
    derived_product_instances = []
    feedback_success_message = None

    # Check if we are redirecting from a feedback submission
    show_derived_for_search_id = request.args.get('show_derived_for_search_id')
    if show_derived_for_search_id:
        try:
            search_id = int(show_derived_for_search_id)
            print(f"Redirected from feedback. Attempting to fetch derived products for Search ID: {search_id}")

            # Fetch the original search query text for display
            search_query_url = f'{DJANGO_API_BASE_URL}/search_queries/{search_id}/'
            try:
                sq_response = requests.get(search_query_url)
                sq_response.raise_for_status()
                search_query_data = sq_response.json()
                search_query_text = search_query_data.get('query_text', '')
                # Also re-fetch the search results to display them again
                search_results = search_query_data.get('results', {})
            except requests.exceptions.RequestException as e:
                print(f"Error fetching original search query for ID {search_id}: {e}")
                search_query_text = f"[Error fetching query for ID {search_id}]"

            # Fetch derived product instances for this search_id
            derived_url = f'{DJANGO_API_BASE_URL}/derived_product_instances/?search_query={search_id}'
            derived_response = requests.get(derived_url)
            derived_response.raise_for_status()
            derived_product_instances = derived_response.json()
            print(f"Fetched {len(derived_product_instances)} derived product instances for Search ID {search_id}.")
            feedback_success_message = "Feedback saved and structured products derived successfully!"

        except requests.exceptions.RequestException as e:
            error_message = f"Error fetching derived products from Django API: {e}"
            print(f"API Request Error fetching derived products: {e}")
        except ValueError:
            error_message = "Invalid search ID for derived products."
            print(f"Invalid search ID for derived products: {show_derived_for_search_id}")


    if request.method == 'POST':
        search_query_text = request.form.get('query_text', '').strip()

        if search_query_text:
            # --- Call the Django API for Universal Search ---
            search_url = f'{DJANGO_API_BASE_URL}/search/'
            print(f"Calling Django search API at {search_url} with query: '{search_query_text}'")
            try:
                response = requests.post(search_url, json={'query': search_query_text})
                response.raise_for_status()

                api_response_data = response.json()

                search_id = api_response_data.get('id')
                print(f"Received Search ID: {search_id}")

                # --- Process results from the API response ---
                results_by_website = api_response_data.get('results', {})

                for site_name in WEBSITES:
                    search_results[site_name] = results_by_website.get(site_name, [])
                    print(f"Received {len(search_results[site_name])} results for {site_name}")

                # Check for scraping errors from Django
                if api_response_data.get('scraping_errors'):
                    error_messages_list = []
                    for site, err_msg in api_response_data['scraping_errors'].items():
                        error_messages_list.append(f"{site}: {err_msg}")
                    error_message = "Some scraping errors occurred: " + "; ".join(error_messages_list)

            except requests.exceptions.RequestException as e:
                error_message = f"Error calling Django search API: {e}"
                print(f"API Request Error: {e}")
                if response is not None and response.content:
                    try:
                        error_details = response.json()
                        error_message = f"API Error: {error_details.get('error', str(e))}"
                        print(f"API Error Details: {error_details}")
                    except json.JSONDecodeError:
                        error_message = f"API Error: {response.text[:200]}..."
                        print(f"API Error Response (non-JSON): {response.text}")
                search_id = None
        else:
            error_message = "Please enter a search query."

    # Render the template, passing the data
    return render_template(
        'index.html',
        search_query_text=search_query_text,
        search_id=search_id,
        search_results=search_results,
        error_message=error_message,
        websites=WEBSITES,
        derived_product_instances=derived_product_instances,
        feedback_success_message=feedback_success_message
    )

@app.route('/submit_feedback', methods=['POST'])
def submit_feedback():
    """
    Handles the submission of user feedback (selected results, manual correction).
    Expects data as form-urlencoded from the HTML form.
    """
    search_id = request.form.get('search_id')
    query_text = request.form.get('query_text') # Get original query text from hidden field
    selected_result_ids = []
    for key, value in request.form.items():
        if key.startswith('selected_result_'):
            try:
                result_id = int(key.replace('selected_result_', ''))
                selected_result_ids.append(result_id)
            except ValueError:
                print(f"Warning: Could not parse result ID from checkbox key: {key}")

    manual_correction_text = request.form.get('manual_correction_text', '').strip()

    print(f"Received feedback for Search ID: {search_id}")
    print(f"Selected Result IDs: {selected_result_ids}")
    print(f"Manual Correction Text: '{manual_correction_text}'")

    if not search_id:
        return jsonify({"error": "Search ID is missing from feedback."}), 400

    # Call the Django API to submit feedback
    feedback_url = f'{DJANGO_API_BASE_URL}/feedback/' # Corrected endpoint
    feedback_data = {
        'search_id': int(search_id),
        'selected_result_ids': selected_result_ids,
        'manual_correction_text': manual_correction_text,
        'query_text': query_text # Pass query_text to Django if needed for future logic
    }

    print(f"Sending feedback to Django API at {feedback_url}")
    try:
        response = requests.post(feedback_url, json=feedback_data)
        response.raise_for_status()
        api_response_data = response.json()
        print("Feedback successfully sent to Django API.")
        print(f"Feedback API Response: {api_response_data}")

        # Redirect back to the index page, passing the search_id to display derived products
        return redirect(url_for('index', show_derived_for_search_id=search_id))

    except requests.exceptions.RequestException as e:
        error_message = f"Error sending feedback to Django API: {e}"
        print(f"Feedback API Request Error: {e}")
        response_status = 500
        if response is not None:
            response_status = response.status_code
            if response.content:
                try:
                    error_details = response.json()
                    error_message = f"API Error: {error_details.get('error', str(e))}"
                    print(f"Feedback API Error Details: {error_details}")
                except json.JSONDecodeError:
                    error_message = f"API Error: {response.text[:200]}..."
                    print(f"Feedback API Error Response (non-JSON): {response.text}")

        return jsonify({"error": error_message}), response_status


if __name__ == '__main__':
    app.run(debug=True, port=5000)