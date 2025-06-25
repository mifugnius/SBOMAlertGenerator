import os
import smtplib
import json
from email.message import EmailMessage
from utils.models.SMTP_parameters import SMTP_parameters
from dotenv import load_dotenv

SBOM_FILE_NAME = "sbom.json"
REPORT_FILE_NAME = "report.pdf"

def add_file_to_email(email, attachment_path, subtype):
    with open(attachment_path, 'rb') as f:
        email.add_attachment(f.read(), maintype='application', subtype = 'json', filename = os.path.basename(attachment_path))

    return email

def send_email(email_receiver, env_config: SMTP_parameters):
    # Load environment variables
    load_dotenv()

    SMTP_SERVER_NAME = env_config.smtp_server_name or os.getenv("SMTP_SERVER_NAME")
    SMTP_PORT = env_config.smtp_port or os.getenv("SMTP_PORT")
    SMTP_USERNAME = env_config.smtp_username or os.getenv("SMTP_USERNAME")
    SMTP_MASTER_PASSWORD = env_config.smtp_master_password or os.getenv("SMTP_MASTER_PASSWORD")
    SMTP_EMAIL_FROM = env_config.email_from or os.getenv("EMAIL_FROM")

    EMAIL_SUBJECT = "Vulnerability Scan"

    email = EmailMessage()
    email["Subject"] = EMAIL_SUBJECT
    email["To"] = email_receiver
    email["From"] = SMTP_EMAIL_FROM

    add_file_to_email(email, SBOM_FILE_NAME, 'json')
    add_file_to_email(email, REPORT_FILE_NAME, 'pdf')

    with smtplib.SMTP(SMTP_SERVER_NAME, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USERNAME, SMTP_MASTER_PASSWORD)
        server.send_message(email)
    
    print(f"Email Sent to {email_receiver}")
 