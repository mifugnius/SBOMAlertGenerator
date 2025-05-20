import os
import subprocess
import shutil
import argparse
import sys
from utils.email_utils import send_email

TMP_DIRECTORY_SUBPATH = '/tmp/'

SBOM_FILE_NAME = "sbom.json"

TABLE_COLUMN_COUNT = 8

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

def generate_SBOM(repo_url):
	result = subprocess.run(["syft", get_repository_local_directory_name(repo_url), "-o", "json"], stdout=subprocess.PIPE, check=True)
	
	with open(SBOM_FILE_NAME, "wb") as f:
		f.write(result.stdout)

def generate_html_table(vulnerabilities_table_string):
	print(vulnerabilities_table_string)
	lines = vulnerabilities_table_string.strip().split("\n")
	html = '<table border="1" cellpadding="5" cellspacing="0" style="border-collapse:collapse; font-family:sans-serif;">'

	header = lines[0].split()
	html += ("<thead><tr>" + "".join(f"<th>{header_row}</th>" for header_row in header) + "</tr></thead>")

	html += "<tbody>"
	
	for line in lines[1:]:
		columns = line.split(None, len(header) - 1)

		# Add empty column if FIXED-IN is empty
		if (len(columns) < TABLE_COLUMN_COUNT):
			columns.insert(2, "")

		# Make Vulnerability column into a OSV hyperlink
		columns[4] = f'<a href="https://osv.dev/vulnerability/{columns[4]}" target="_blank">{columns[4]}</a>'
		
		html += ("<tr>" + "".join(f"<td>{column}</td>" for column in columns) + "</tr>")

	html += "</tbody></table>"

	return html

def generate_vulnerability_report():
	result = subprocess.run(["grype", f"sbom:{SBOM_FILE_NAME}", "-o", "table"], stdout=subprocess.PIPE, check=True, text=True)
	return result.stdout

def repository_has_vulnerabilities(output):
	return output != "No vulnerabilities found\n"

def main():
	parser = argparse.ArgumentParser(description="SBOMAlertGenerator: Generate Alerts for a Repository")

	parser.add_argument('repository_url', type=str, help='URL of the Git repository to analyze')
	parser.add_argument('--branch', type=str, help='Repository branch to analyze')
	parser.add_argument('--no-email', action='store_false', dest='send_email', help='Disable sending email')
	parser.add_argument('--email-address', type=str, help='Email address to send alerts to')

	args = parser.parse_args()
	print(args)

	repo_url = args.repository_url
	email_flag = args.send_email
	email_address = args.email_address
	branch = args.branch
	
	clone_repository(repo_url, branch)
	generate_SBOM(repo_url)
	vulnerabilities_output = generate_vulnerability_report()
	
	if (email_flag and email_address is not None):
		send_email(email_address, generate_html_table(vulnerabilities_output))

	sys.exit(1 if repository_has_vulnerabilities(vulnerabilities_output) else 0)

if __name__ == "__main__":
    main()