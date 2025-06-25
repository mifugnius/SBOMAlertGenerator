class SMTP_parameters:
    def __init__(self, smtp_server_name, smtp_port, smtp_username, smtp_master_password, email_from):
        self.smtp_server_name = smtp_server_name
        self.smtp_port = smtp_port
        self.smtp_username = smtp_username
        self.smtp_master_password = smtp_master_password
        self.email_from = email_from