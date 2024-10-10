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

1. Syslog (local)
2. Email (Microsoft Exchange)
3. Database (alert_records.db)
4. Log file (alert_log.json)

Future improvements:

1. Send to remote syslog e.g. (rsyslog, wazuh integration etc.)
2. Grafana dashboard for alert_records.db
3. Logrotation for alert_log.json with backup
4. Flask frontend
5. Dockerize the app

'''


app = Flask(__name__)

load_dotenv()

logger = logging.getLogger()
logger.setLevel(logging.INFO)
syslog_handler = logging.handlers.SysLogHandler(address='/dev/log')  # Use 'localhost' and port 514 for remote syslog
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
syslog_handler.setFormatter(formatter)
logger.addHandler(syslog_handler)
# logger.info('Send to syslog')

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
    if request.is_json:
        webhook_data = request.get_json()
        '''
        {"message": "%(message)s"}
        '''
        print("Webhook data received:", json.dumps(webhook_data, indent=4))
        logger.info('Webhook data received:', json.dumps(webhook_data, indent=4))
        sendEmail(webhook_data)
        toDatabase(webhook_data)
        # Save to a log file
        with open('alert_log.json', 'a') as log_file:
            json.dump(webhook_data, log_file)
            log_file.write('\n')

        return jsonify({'status': 'success', 'message': 'Webhook received'}), 200
    else:
        return jsonify({'status': 'error', 'message': 'Invalid payload'}), 400
    

if __name__ == '__main__':
    # Flask run
    app.run(host='0.0.0.0', port=5000)