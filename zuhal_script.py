import re
import dns.resolver
import smtplib
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import json
import mysql.connector
import os
import sys

DISPOSABLE_DOMAINS_URL = "https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains.txt"

# Fetch and load disposable email domains
def load_disposable_domains():
    try:
        response = requests.get(DISPOSABLE_DOMAINS_URL, timeout=10)
        response.raise_for_status()
        return set(response.text.splitlines())
    except requests.RequestException as e:
        print(f"Error fetching disposable domains list: {e}")
        return set()

# Validate email syntax
def validate_syntax(email):
    regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return re.match(regex, email) is not None

# Check if domain exists
def check_domain(domain):
    try:
        dns.resolver.resolve(domain, 'MX', lifetime=5)
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        try:
            dns.resolver.resolve(domain, 'A', lifetime=5)
            return True
        except:
            return False
    except Exception as e:
        print(f"Error checking domain {domain}: {e}")
        return False

# Check if domain is disposable
def is_disposable(domain, disposable_domains):
    return domain in disposable_domains

# Check if the domain is accept-all
def is_accept_all(domain):
    fake_email = f"fakeaddresssgdfjhdbcywug@{domain}"
    try:
        mx_records = dns.resolver.resolve(domain, 'MX', lifetime=5)
        mx_host = str(mx_records[0].exchange)

        # Connect to mail server
        server = smtplib.SMTP(mx_host, timeout=5)
        server.helo()
        server.mail("rakumar@gmail.in")
        code, _ = server.rcpt(fake_email)
        server.quit()

        if code == 250:
            return True  # Accept-all domain
        return False
    except smtplib.SMTPConnectError:
        print(f"Unable to connect to mail server for domain: {domain}")
        return None
    except Exception as e:
        print(f"Error checking accept-all for {domain}: {e}")
        return None

# Perform SMTP verification across multiple MX records
def verify_email(email):
    domain = email.split('@')[-1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX', lifetime=5)
        mx_records = sorted(mx_records, key=lambda x: x.preference)

        for mx in mx_records:
            mx_host = str(mx.exchange)

            try:
                server = smtplib.SMTP(mx_host, timeout=5)
                server.helo()
                server.mail("rakumar@gmail.in")
                code, _ = server.rcpt(email)
                server.quit()

                if code == 250:
                    return True  # Valid email address
                elif code in {550, 553}:
                    return False  # Explicit rejection
                elif code in {450, 451}:
                    return "TEMPORARY_FAILURE"
            except (smtplib.SMTPConnectError, socket.error, BrokenPipeError) as e:
                print(f"Error verifying email {email} with {mx_host}: {e}")
                continue
            except Exception as e:
                print(f"Error verifying email {email} with {mx_host}: {e}")
                continue

        return None
    except dns.resolver.NoAnswer:
        print(f"No MX records found for domain {domain}")
        return None
    except Exception as e:
        print(f"Error verifying email {email}: {e}")
        return None

# Categorize email
def categorize_email(email_entry, disposable_domains):
    email = email_entry["email"]
    email_id = email_entry["id"]

    if not validate_syntax(email):
        return {"id": email_id, "email": email, "status": "Invalid", "response": "Syntax error", "score":0}

    domain = email.split('@')[-1]

    if not check_domain(domain):
        return {"id": email_id, "email": email, "status": "Invalid", "response": "Domain doesn't exists", "score":0}

    if is_disposable(domain, disposable_domains):
        return {"id": email_id, "email": email, "status": "Disposable", "response": "Email is disposable", "score":0}

    accept_all_status = is_accept_all(domain)
    if accept_all_status is True:
        return {"id": email_id, "email": email, "status": "Accept All", "response": "Accept All Domain", "score":0}

    smtp_result = verify_email(email)
    if smtp_result == "TEMPORARY_FAILURE":
        return {"id": email_id, "email": email, "status": "Valid", "response": "Temporary failure detected", "score":1}
    elif smtp_result is None:
        return {"id": email_id, "email": email, "status": "Unknown", "response": "SMPT verification failed", "score":0}
    elif smtp_result:
        return {"id": email_id, "email": email, "status": "Valid", "response": "success", "score":1 }
    else:
        return {"id": email_id, "email": email, "status": "Invalid", "response": "Rejected by server", "score":0 }


# Process emails in parallel
def process_emails_parallel(email_entries, disposable_domains, db_connection, log_file_path):
    with ThreadPoolExecutor(max_workers=20) as executor, open(log_file_path, "a") as log_file:
        future_to_email = {executor.submit(categorize_email, email_entry, disposable_domains): email_entry for email_entry in email_entries}
        for future in as_completed(future_to_email):
            try:
                result = future.result()
                
                #Log result to file
                log_file.write(f"ID: {result['id']}, Email: {result['email']}, Status: {result['status']}, Response: {result['response']}, Score: { result['score'] } \n")
                log_file.flush()  # Ensure logs are written immediately 

                #update the DB
                update_email_status_in_db(db_connection, result)

                # print result for debugging
                print(result)

            except Exception as e:
                email_entry = future_to_email[future]
                error_result = {"id": email_entry["id"], "email": email_entry["email"], "status": f"Error ({e})"}

                # Log error to file
                log_file.write(f"ID: {error_result['id']}, Email: {error_result['email']}, Status: {error_result['status']}\n")
                log_file.flush()

                # Update database with error status
                update_email_status_in_db(db_connection, error_result)

                print(error_result)


def update_email_status_in_db(db_connection, result):
    try:
        cursor = db_connection.cursor()
        update_query = """
            UPDATE emails
            SET status = %s,
                response = %s,
                score = %s
            WHERE id = %s;
        """
        cursor.execute(update_query, (result["status"], result["response"], result["score"], result["id"]))
        db_connection.commit()
    except Exception as e:
        print(f"Error updating database for ID {result['id']}: {e}")
    finally:
        cursor.close()

# Function to check if the required number of arguments is passed
def validate_args(args):
    if len(args) < 5:
        print("Error: Missing arguments. You need to provide at least 5 arguments for DB connection.")
        print("Usage: python script.py <host> <user> <password> <database> <json path>")
        sys.exit(1)

# Function to safely get an argument, falling back to a default value if not provided
def get_arg(args, index, default_value):
    try:
        return args[index]
    except IndexError:
        return default_value


# Main function
def main():
    disposable_domains = load_disposable_domains()
   
    log_file_path = "email_validation_log.txt"
    args = sys.argv
    
    # Validate arguments
    validate_args(args)

    host = get_arg(args, 1, "localhost")
    user = get_arg(args, 2, "root")
    password = get_arg(args, 3, "ChicMic@2024")
    database = get_arg(args, 4, "test_python_script")
    file_path = get_arg(args, 5, "demo.json")

    # Connect to database
    db_connection = mysql.connector.connect(
        host=host,
        user=user,   
        password=password,  
        database=database 
    )

    try: 
        # Clear logs from the starting 
        open(log_file_path, "w").close()

        with open(file_path, "r") as file:
            emails_entries = json.load(file)
        
        # Process emails and log/updates in real time
        process_emails_parallel(emails_entries, disposable_domains, db_connection, log_file_path)

    except Exception as e:
        print(f"Error: {e}")
    
    finally:
        if db_connection.is_connected():
            db_connection.close()


if __name__ == "__main__":
    main()

