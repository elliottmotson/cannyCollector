from flask import Flask, request, jsonify
from dotenv import load_dotenv
from exchangelib import Credentials, Account, Message, DELEGATE
import json
import sqlite3
import os
import logging
import logging.handlers


'''

Incoming openCanary agent data is sent to:

1. Email (Microsoft Exchange)
2. Sqlite3 Database (alert_records.db)
3. Log file (alert_log.json)

Future improvements:

1. Send to remote syslog e.g. (rsyslog, wazuh integration etc.)
2. Grafana dashboard for alert_records.db
3. Logrotation for alert_log.json with backup
4. Flask frontend
5. Dockerize the app [Done]

'''

app = Flask(__name__)

load_dotenv()

# Fetch env
sender_email = os.getenv('SENDER_EMAIL')
receiver_email = os.getenv('RECEIVER_EMAIL')
subject = os.getenv('EMAIL_SUBJECT')
body = ""
exchange_username = os.getenv('EXCHANGE_USERNAME')
exchange_password = os.getenv('EXCHANGE_PASSWORD')
exchange_server = os.getenv('EXCHANGE_SERVER')

def sendEmail(webhook_data):
    try:
        # Create creds for sender account
        credentials = Credentials(username=exchange_username, password=exchange_password)
        account = Account(primary_smtp_address=sender_email, credentials=credentials, autodiscover=False, config=None, access_type=DELEGATE)

        message = Message(
            account=account,
            subject=subject,
            body=f"Oi!\n\nSomebodies triggered the honeypot:\n\n{json.dumps(webhook_data, indent=4)}\n\nRegards,\nCanny Collector",
            to_recipients=[receiver_email]
        )
        message.send()
        print("Email sent successfully")

    except Exception as e:
        print("Error sending email:", e)


def toDatabase(webhook_data):
    try:
        conn = sqlite3.connect('alert_records.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alert_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data TEXT NOT NULL,
                received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            INSERT INTO alert_records (data) VALUES (?)
        ''', (json.dumps(webhook_data),))
        conn.commit()
        print("Webhook data inserted into the database successfully")
    except sqlite3.Error as e:
        print("Error interacting with the database:", e)
    finally:
        if conn:
            conn.close()


# Route for OpenCanary to hit
@app.route('/collect', methods=['POST'])
def openCanary_webhook():
    print("Raw Request Headers:", request.headers, "\n")
    if request.is_json:
        try:
            webhook_data = request.get_json()
            if 'message' in webhook_data:
                message_data = json.loads(webhook_data['message'])  # String to JSON
                webhook_data['message'] = message_data
            print("Parsed webhook data:", json.dumps(webhook_data, indent=4))
            sendEmail(webhook_data)
            toDatabase(webhook_data)
            with open('alert_log.json', 'a') as log_file:
                json.dump(webhook_data, log_file)
                log_file.write('\n')
            return jsonify({'status': 'success', 'message': 'Webhook received'}), 200
        except Exception as e:
            print("Error processing request:", e)
            return jsonify({'status': 'error', 'message': 'Invalid JSON payload'}), 400
    else:
        print("Invalid payload format. Expected JSON. Content-Type:", request.content_type)
        return jsonify({'status': 'error', 'message': 'Invalid payload format, expected JSON'}), 400

    

if __name__ == '__main__':
    # Flask run
    app.run(host='0.0.0.0', port=5000)