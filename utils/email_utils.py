import os
import smtplib
import json
from email.message import EmailMessage
from dotenv import load_dotenv

SBOM_FILE_NAME = "sbom.json"

# Load environment variables
load_dotenv()

SMTP_SERVER_NAME = os.getenv("SMTP_SERVER_NAME")
SMTP_PORT = os.getenv("SMTP_PORT")
SMTP_USERNAME = os.getenv("SMTP_USERNAME")
SMTP_MASTER_PASSWORD = os.getenv("SMTP_MASTER_PASSWORD")
SMTP_EMAIL_FROM = os.getenv("EMAIL_FROM")

EMAIL_SUBJECT = "Vulnerability Scan"
VILNERABILITY_REPORT_FILE_NAME = "vulnerability_report.json"


def add_file_to_email(email, attachment_path):
    with open(attachment_path, 'rb') as f:
        email.add_attachment(f.read(), maintype='application', subtype = 'json', filename = os.path.basename(attachment_path))

    return email

def send_email(email_receiver, content):
    email = EmailMessage()
    email["Subject"] = EMAIL_SUBJECT
    email["To"] = email_receiver
    email["From"] = SMTP_EMAIL_FROM
    email.add_alternative(content, subtype = "html")

    add_file_to_email(email, SBOM_FILE_NAME)

    with smtplib.SMTP(SMTP_SERVER_NAME, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_MASTER_PASSWORD)
        server.send_message(email)
    
    print(f"Email Sent to {email_receiver}")
 