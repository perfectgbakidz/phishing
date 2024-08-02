import json
import logging
import re
import requests
import subprocess
import pandas as pd
from urllib.parse import urlparse
from googleapiclient.discovery import build
from telethon import TelegramClient, events

# Hardcoded list of known phishing links
known_phishing_links = [
    # Add known phishing links here
]

# URL of the website where phishing links will be sent
PHISHING_WEBSITE_URL = "https://example.com/report_phishing_link"

# Read Telegram credentials
with open('telegram_credentials.json') as f:
    telegram_credentials = json.load(f)

# Read Google API key
with open('google_api_key.txt') as f:
    google_api_key = f.read().strip()

# Read VirusTotal API key
with open('virustotal_api_key.txt') as f:
    virustotal_api_key = f.read().strip()

# Set up logging
logging.basicConfig(filename='phishing_links.log', level=logging.INFO)
logger = logging.getLogger()

# Suppress googleapiclient cache warnings
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)

# Google Safe Browsing setup
def is_phishing_link_google(url):
    service = build("safebrowsing", "v4", developerKey=google_api_key)
    body = {
        "client": {
            "clientId": "yourcompany",
            "clientVersion": "1.5.2"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }
    request = service.threatMatches().find(body=body)
    response = request.execute()
    return bool(response.get("matches"))

# VirusTotal setup
def is_phishing_link_virustotal(url):
    headers = {
        "x-apikey": virustotal_api_key
    }
    params = {
        "url": url
    }
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url}", headers=headers, params=params)
    if response.status_code == 200:
        json_response = response.json()
        if 'data' in json_response and 'attributes' in json_response['data']:
            attributes = json_response['data']['attributes']
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            if last_analysis_stats.get('malicious', 0) > 0 or last_analysis_stats.get('suspicious', 0) > 0:
                return True
    return False

# Check against the hardcoded list of known phishing links
def is_phishing_link_known(url):
    return url in known_phishing_links

# Combined check using all methods
def is_phishing_link(url):
    return is_phishing_link_google(url) or is_phishing_link_virustotal(url) or is_phishing_link_known(url)

# Link extraction utility
def extract_links(text):
    regex = r"(https?://\S+)"
    return re.findall(regex, text)

# Logging utility
def log_phishing_link(link, username, label):
    log_message = f"{link},{username},{label}"
    print(log_message)
    logger.info(log_message)

# Function to send phishing link to the website
def send_phishing_link_to_website(link):
    try:
        response = requests.post(PHISHING_WEBSITE_URL, json={"phishing_link": link})
        if response.status_code == 200:
            print(f"Successfully sent phishing link to website: {link}")
        else:
            print(f"Failed to send phishing link to website: {link}, Status Code: {response.status_code}")
    except Exception as e:
        print(f"Error sending phishing link to website: {link}, Error: {str(e)}")

# Telethon setup
api_id = telegram_credentials['api_id']
api_hash = telegram_credentials['api_hash']
client = TelegramClient('session_name', api_id, api_hash)

@client.on(events.NewMessage)
async def handle_message(event):
    message = event.message.message
    sender = await event.get_sender()
    username = sender.username if sender and sender.username else f'{sender.id}'
    links = extract_links(message)
    for link in links:
        label = 'phishing' if is_phishing_link(link) else 'legit'
        log_phishing_link(link, username, label)
        if label == 'phishing':
            send_phishing_link_to_website(link)

# Data Preprocessing for Weka
def preprocess_data(log_file):
    data = []
    with open(log_file, 'r') as file:
        for line in file:
            link, username, label = line.strip().split(',')
            data.append([link, username, label])
    df = pd.DataFrame(data, columns=['link', 'username', 'label'])
    df.to_csv('phishing_data.csv', index=False)
    return 'phishing_data.csv'

# Function to run Weka CLI for model evaluation
def run_weka_evaluation(csv_file):
    # Convert CSV to ARFF using Weka CLI
    arff_file = csv_file.replace('.csv', '.arff')
    subprocess.run(f'java -cp weka.jar weka.core.converters.CSVLoader {csv_file} > {arff_file}', shell=True)

    # Train and evaluate model using Weka CLI
    result = subprocess.run(['java', '-cp', 'weka.jar', 'weka.classifiers.trees.J48', '-t', arff_file, '-x', '10'], capture_output=True, text=True)
    print(result.stdout)
    
    # Parse and display evaluation metrics
    for line in result.stdout.split('\n'):
        if "Correctly Classified Instances" in line or "Incorrectly Classified Instances" in line:
            print(line)
        if "Weighted Avg." in line:
            metrics = line.split()
            print(f"Precision: {metrics[2]}")
            print(f"Recall: {metrics[3]}")
            print(f"F1 Score: {metrics[4]}")

# Main function
if __name__ == '__main__':
    with client:
        client.run_until_disconnected()

    csv_file = preprocess_data('phishing_links.log')
    run_weka_evaluation(csv_file)
