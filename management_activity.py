import requests
import json
import logging
import os
import re
from datetime import datetime, timedelta
import traceback
from requests.adapters import HTTPAdapter
from urllib3 import Retry

# Constants
QUERY_WINDOW_SIZE = 60  # Minutes
REQUEST_TIMEOUT = 120
API_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
EVENT_OUTPUT_FILE_BASE = "azure_ad_logs/management_activity_event_output"
EVENT_OUTPUT_FILE_EXTENSION = ".json"
AUDIT_INPUT_LOG_FILE = "azure_ad_logs/management_input.log"
MAX_FILE_SIZE_MB = 500

# Get a session with retries
def get_session_with_retries():
    session = requests.Session()
    retries = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    return session

# Get OAuth token
def get_access_token(session, tenant_id, client_id, client_secret):
    url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
    body = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://manage.office.com/.default",
    }
    response = session.post(url, data=body)
    response.raise_for_status()
    return response.json()["access_token"]

# Get new file name for saving logs
def get_new_file_name(base_name, extension, index):
    return f"{base_name}_{index}{extension}"

# Collect logs from Management Activity API
def collect_logs(session, token, tenant_id, start_date_time, end_date_time, base_file_name, extension):
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }
    base_url = f"https://manage.office.com/api/v1.0/{tenant_id}/activity/feed/subscriptions/content"
    params = {
        "contentType": "Audit.AzureActiveDirectory",
        "startTime": start_date_time,
        "endTime": end_date_time
    }

    file_index = 0
    current_file_name = get_new_file_name(base_file_name, extension, file_index)
    current_file_size = 0
    total_logs = 0

    response = session.get(base_url, headers=headers, params=params, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    content_list = response.json()  # List of content metadata

    for content in content_list:
        content_uri = content.get("contentUri")
        if not content_uri:
            continue

        # Fetch the actual log data using contentUri
        event_response = session.get(content_uri, headers=headers, timeout=REQUEST_TIMEOUT)
        event_response.raise_for_status()
        event_data = event_response.json()  # Actual event details

        # Write events to file
        with open(current_file_name, "a") as file:
            for event in event_data:
                json.dump(event, file, ensure_ascii=False)
                file.write("\n")
                current_file_size += len(json.dumps(event, ensure_ascii=False)) + 1
                total_logs += 1

                # Split files if size exceeds the limit
                if current_file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
                    file_index += 1
                    current_file_name = get_new_file_name(base_file_name, extension, file_index)
                    current_file_size = 0

    logging.info(f"Collected {total_logs} Azure AD audit logs from {start_date_time} to {end_date_time}")
    return total_logs

# Main function
def main():
    try:
        # Ensure the log directory exists before writing logs
        log_dir = os.path.dirname(AUDIT_INPUT_LOG_FILE)
        os.makedirs(log_dir, exist_ok=True)

        logging.basicConfig(
            filename=AUDIT_INPUT_LOG_FILE,
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        tenant_id = os.getenv("TENANT_ID")
        client_id = os.getenv("CLIENT_ID")
        client_secret = os.getenv("CLIENT_SECRET")

        if not (tenant_id and client_id and client_secret):
            raise ValueError("Missing required environment variables (TENANT_ID, CLIENT_ID, CLIENT_SECRET)")

        start_date_time = input("Enter start date-time (YYYY-MM-DDTHH:MM:SSZ): ")
        end_date_time = input("Enter end date-time (YYYY-MM-DDTHH:MM:SSZ): ")

        session = get_session_with_retries()
        token = get_access_token(session, tenant_id, client_id, client_secret)

        total_logs = collect_logs(session, token, tenant_id, start_date_time, end_date_time, EVENT_OUTPUT_FILE_BASE, EVENT_OUTPUT_FILE_EXTENSION)
        logging.info(f"Total logs collected: {total_logs}")

    except Exception as e:
        logging.error(f"Error: {str(e)}")
        logging.error(traceback.format_exc())

if __name__ == "__main__":
    main()
