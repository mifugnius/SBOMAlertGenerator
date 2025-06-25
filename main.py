import os
import subprocess
import shutil
import argparse
import sys
import json
import threading
import psutil
import time
import linecache
from utils.email_utils import send_email
from utils.report_util import create_security_report_pdf
from utils.models.SMTP_parameters import SMTP_parameters

TMP_DIRECTORY_SUBPATH = '/tmp/'

SBOM_FILE_NAME = "sbom.json"

max_rss = 0
max_rss_info = {}

# VILNERABILITY_REPORT_FILE_NAME = "vulnerability_report.json"

def get_repository_name(repo_url):
	repo_name = repo_url.split('/')[-1]
	
	if repo_name.endswith('.git'):
		repo_name = repo_name[:-4]

	return repo_name

def get_repository_local_directory_name(repo_url):
    return os.getcwd() + TMP_DIRECTORY_SUBPATH + get_repository_name(repo_url)

def remove_local_directory(directory_name):
	shutil.rmtree(os.getcwd() + TMP_DIRECTORY_SUBPATH + directory_name)
	

def clone_repository(repo_url, branch):
    # Get directory to clone to
	directory_clone_to = get_repository_local_directory_name(repo_url)

	if os.path.exists(directory_clone_to):
		print(f"Directory {directory_clone_to} already exists. Removing the directory.")
		remove_local_directory(get_repository_name(repo_url))
	try:
		if branch:
			subprocess.run(["git", "clone", "--branch", branch, "--depth", "1", repo_url, directory_clone_to], check=True)
		else:
			subprocess.run(["git", "clone", repo_url, directory_clone_to], check=True)
	except:
		print("Git error. Check repository name, branch name or access rights to the repository")
		sys,exit(1)


	return directory_clone_to

def generate_SBOM(directory):
	result = subprocess.run(["syft", directory, "-o", "json"], stdout=subprocess.PIPE, check=True)

	sbom_data = json.loads(result.stdout)

	readable_json_string = json.dumps(sbom_data, indent=4)
	
	with open(SBOM_FILE_NAME, "w", encoding="utf-8") as f:
		f.write(readable_json_string)

def generate_vulnerability_report():
	result = subprocess.run(["grype", f"sbom:{SBOM_FILE_NAME}", "-o", "table"], stdout=subprocess.PIPE, check=True, text=True)
	return result.stdout

def repository_has_vulnerabilities(output):
	return output != "No vulnerabilities found\n"

def track_memory():
    global max_rss, max_rss_info
    process = psutil.Process(os.getpid())
    while True:
        rss = process.memory_info().rss
        if rss > max_rss:
            max_rss = rss
            # Copy last trace location
            info = max_rss_info.copy()
            print(f"\n[MEMORY PEAK] {rss / 1024**2:.2f} MB")
            if info:
                print(f"  ↳ At {info['filename']}:{info['lineno']}")
                line = linecache.getline(info['filename'], info['lineno']).strip()
                print(f"  ↳ Line: {line}")
        time.sleep(0.01)

def trace_calls(frame, event, arg):
    if event == 'line':
        max_rss_info['filename'] = frame.f_code.co_filename
        max_rss_info['lineno'] = frame.f_lineno
    return trace_calls

def start_tracing():
    sys.settrace(trace_calls)
    threading.settrace(trace_calls)

def main():
	# Uncomment for memory usage tracking
	# threading.Thread(target=track_memory, daemon=True).start()

	parser = argparse.ArgumentParser(description="SBOMAlertGenerator: Generate Alerts for a Repository")

	parser.add_argument('--repository', type=str, help='URL of the Git repository to analyze')
	parser.add_argument('--branch', type=str, help='Repository branch to analyze')
	parser.add_argument('-n', '--no-email', action='store_false', dest='send_email', help='Disable sending email (used when --email-address is not specified)')
	parser.add_argument('--email-address', type=str, help='Email address to send alerts to (used when --no-email is not specified)')
	parser.add_argument('--directory-to-scan', type=str, help='Local directory to scan')
	parser.add_argument('--smtp-server-name', type=str, help='SMTP server name (required if no .env configuration)')
	parser.add_argument('--smtp-port', type=str, help='SMTP server port (required if no .env configuration)')
	parser.add_argument('--smtp-username', type=str, help='SMTP username (required if no .env configuration)')
	parser.add_argument('--smtp-master-password', type=str, help='SMTP server master password (required if no .env configuration)')
	parser.add_argument('--email-from', type=str, help='Email to send email from (required if no .env configuration)')


	args = parser.parse_args()
	
	repo_url = args.repository
	email_flag = args.send_email
	email_address = args.email_address
	branch = args.branch
	directory_to_scan = args.directory_to_scan

	# no .env (CI) properties
	env_config = SMTP_parameters(
		args.smtp_server_name, 
		args.smtp_port, 
		args.smtp_username, 
		args.smtp_master_password, 
		args.email_from)

	if (repo_url):
		clone_repository(repo_url, branch)
		directory_to_scan = get_repository_local_directory_name(repo_url)

	generate_SBOM(directory_to_scan)
	vulnerabilities_output = generate_vulnerability_report()

	print(vulnerabilities_output)
	
	if (email_flag and email_address is not None):
		create_security_report_pdf(vulnerabilities_output, os.path.basename(directory_to_scan))
		send_email(email_address, env_config)

	# Uncomment for memory usage tracking
	#print(f"max: {max_rss}")

	sys.exit(1 if repository_has_vulnerabilities(vulnerabilities_output) else 0)

if __name__ == "__main__":
    main()