from flask import Flask, request, jsonify
from dotenv import load_dotenv
from email.mime.text import MIMEText
import json
import sqlite3
import os
import traceback
import logging
import smtplib
import ssl

# logging.basicConfig(level=logging.DEBUG)

# Use TLS 1.2 and disable ssl checking
ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

class CannyCollector:
    def __init__(self):
        load_dotenv()

        # Fetch env variables
        self.sender_email = os.getenv("SENDER_EMAIL")
        self.receiver_email = os.getenv("RECEIVER_EMAIL")
        self.subject = os.getenv("EMAIL_SUBJECT")
        self.body = ""
        self.smtp_username = os.getenv("SMTP_USERNAME")
        self.smtp_password = os.getenv("SMTP_PASSWORD")
        self.smtp_server = os.getenv("SMTP_SERVER")
        self.smtp_port = os.getenv("SMTP_PORT")
        self.smtp_ssl = os.getenv("SMTP_SSL")
        self.smtp_starttls = os.getenv("SMTP_STARTTLS")

        self.data_folder = "./data"
        os.makedirs(self.data_folder, exist_ok=True)

        self.app = Flask(__name__)
        self.app.add_url_rule('/collect', view_func=self.openCanary_webhook, methods=["POST"])

    def send_email(self, webhook_data):
        try:
            msg = MIMEText(f"Oi!\n\nSomebodies triggered the honeypot:\n\n{json.dumps(webhook_data, indent=4)}\n\nRegards,\nCanny Collector",)

            msg['Subject'] = self.subject
            msg['From'] = self.sender_email
            msg['To'] = self.receiver_email


            if (self.smtp_ssl and not self.smtp_starttls):
                s = smtplib.SMTP_SSL(self.smtp_server, self.smtp_port)
            else:
                s = smtplib.SMTP(self.smtp_server, self.smtp_port)

            if (self.smtp_starttls):
                s.ehlo()
                s.starttls(context=ctx)
                s.ehlo()

            if (not self.smtp_username == '' and not self.smtp_password == ''):
                s.login(self.smtp_username, self.smtp_password)

            s.sendmail(self.sender_email, self.receiver_email, msg.as_string())
            print("Email sent successfully")
        except Exception as e:
            print("Error sending email:", e)
            print(traceback.format_exc())

    def to_database(self, webhook_data):
        try:
            conn = sqlite3.connect(os.path.join(self.data_folder, "alert_records.db"))
            cursor = conn.cursor()

            # Create table if it doesn't exist
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS alert_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    dst_host TEXT,
                    dst_port INTEGER,
                    local_time TEXT,
                    local_time_adjusted TEXT,
                    password TEXT,
                    username TEXT,
                    logtype INTEGER,
                    node_id TEXT,
                    src_host TEXT,
                    src_port INTEGER,
                    utc_time TEXT,
                    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

            message = webhook_data.get("message", {})
            dst_host = message.get("dst_host")
            dst_port = message.get("dst_port")
            local_time = message.get("local_time")
            local_time_adjusted = message.get("local_time_adjusted")
            logdata = message.get("logdata", {})
            password = logdata.get("PASSWORD")
            username = logdata.get("USERNAME")
            logtype = message.get("logtype")
            node_id = message.get("node_id")
            src_host = message.get("src_host")
            src_port = message.get("src_port")
            utc_time = message.get("utc_time")

            cursor.execute(
                """
                INSERT INTO alert_records (
                    dst_host, dst_port, local_time, local_time_adjusted, 
                    password, username, logtype, node_id, src_host, src_port, utc_time
                ) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    dst_host,
                    dst_port,
                    local_time,
                    local_time_adjusted,
                    password,
                    username,
                    logtype,
                    node_id,
                    src_host,
                    src_port,
                    utc_time,
                ),
            )

            conn.commit()
            print("Webhook data inserted into the database successfully")
        except sqlite3.Error as e:
            print("Error interacting with the database:", e)
        finally:
            if conn:
                conn.close()

    def openCanary_webhook(self):
        print("Raw Request Headers:", request.headers, "\n")
        if request.is_json:
            try:
                webhook_data = request.get_json()
                if "message" in webhook_data:
                    message_data = json.loads(webhook_data["message"])  # String to JSON
                    webhook_data["message"] = message_data
                print("Parsed webhook data:", json.dumps(webhook_data, indent=4))
                self.send_email(webhook_data)
                self.to_database(webhook_data)
                with open(os.path.join(self.data_folder, "alert_log.json"), "a") as log_file:
                    json.dump(webhook_data, log_file)
                    log_file.write("\n")
                return jsonify({"status": "success", "message": "Webhook received"}), 200
            except Exception as e:
                print("Error processing request:", e)
                return jsonify({"status": "error", "message": "Invalid JSON payload"}), 400
        else:
            print(
                "Invalid payload format. Expected JSON. Content-Type:", request.content_type
            )
            return (
                jsonify(
                    {"status": "error", "message": "Invalid payload format, expected JSON"}
                ),
                400,
            )

    def run(self, host="0.0.0.0", port=5000):
        self.app.run(host=host, port=port)


if __name__ == "__main__":
    collector = CannyCollector()
    collector.run()
