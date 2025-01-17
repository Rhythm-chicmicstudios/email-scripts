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
import socket
import logging
from logging.handlers import RotatingFileHandler

DISPOSABLE_DOMAINS_URL = "https://raw.githubusercontent.com/disposable/disposable-email-domains/master/domains.txt"

# Configure logging
def setup_logging(log_file_path):
    logger = logging.getLogger("EmailValidator")
    logger.setLevel(logging.DEBUG)  # Set to DEBUG to capture all levels of logs

    # Create handlers
    file_handler = RotatingFileHandler(log_file_path, maxBytes=5*1024*1024, backupCount=5)
    file_handler.setLevel(logging.INFO)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # Create formatter and add it to handlers
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(threadName)s - %(filename)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    # Add handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

# Fetch and load disposable email domains
def load_disposable_domains(logger):
    try:
        logger.info("Fetching disposable email domains list...")
        response = requests.get(DISPOSABLE_DOMAINS_URL, timeout=10)
        response.raise_for_status()
        disposable_domains = set(response.text.splitlines())
        logger.info(f"Loaded {len(disposable_domains)} disposable domains.")
        return disposable_domains
    except requests.RequestException as e:
        logger.error(f"Error fetching disposable domains list: {e}")
        return set()

# Validate email syntax
def validate_syntax(email, logger):
    regex = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if re.match(regex, email):
        logger.debug(f"Email '{email}' passed syntax validation.")
        return True
    else:
        logger.debug(f"Email '{email}' failed syntax validation.")
        return False

# Check if domain exists
def check_domain(domain, logger):
    try:
        dns.resolver.resolve(domain, 'MX', lifetime=5)
        logger.debug(f"Domain '{domain}' has MX records.")
        return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
        try:
            dns.resolver.resolve(domain, 'A', lifetime=5)
            logger.debug(f"Domain '{domain}' has A records.")
            return True
        except:
            logger.debug(f"Domain '{domain}' does not exist.")
            return False
    except Exception as e:
        logger.error(f"Error checking domain {domain}: {e}")
        return False

# Check if domain is disposable
def is_disposable(domain, disposable_domains, logger):
    if domain in disposable_domains:
        logger.debug(f"Domain '{domain}' is disposable.")
        return True
    logger.debug(f"Domain '{domain}' is not disposable.")
    return False

# Check if the domain is accept-all
def is_accept_all(domain, logger):
    fake_email = f"fakeaddresssgdfjhdbcywug@{domain}"
    try:
        mx_records = dns.resolver.resolve(domain, 'MX', lifetime=20)
        mx_host = str(mx_records[0].exchange)

        # Connect to mail server
        server = smtplib.SMTP(mx_host, timeout=5)
        server.helo()
        server.mail("rakumar@gmail.in")
        code, _ = server.rcpt(fake_email)
        server.quit()

        if code == 250:
            logger.debug(f"Domain '{domain}' is accept-all.")
            return True  # Accept-all domain
        logger.debug(f"Domain '{domain}' is not accept-all.")
        return False
    except smtplib.SMTPConnectError:
        logger.warning(f"Unable to connect to mail server for domain: {domain}")
        return None
    except Exception as e:
        logger.error(f"Error checking accept-all for {domain}: {e}")
        return None

# Perform SMTP verification across multiple MX records
def verify_email(email, logger):
    domain = email.split('@')[-1]
    try:
        mx_records = dns.resolver.resolve(domain, 'MX', lifetime=10)
        mx_records = sorted(mx_records, key=lambda x: x.preference)
        logger.debug(f"MX records for domain '{domain}': {[mx.exchange for mx in mx_records]}")

        for mx in mx_records:
            mx_host = str(mx.exchange)
            try:
                server = smtplib.SMTP(mx_host, timeout=5)
                server.helo()
                dynamic_email = f"rakumar@{domain}"
                server.mail(dynamic_email)
                code, _ = server.rcpt(email)
                server.quit()

                if code == 250:
                    logger.debug(f"Email '{email}' is valid (accepted by {mx_host}).")
                    return True  # Valid email address
                elif code in {550, 553}:
                    logger.debug(f"Email '{email}' is invalid (rejected by {mx_host} with code {code}).")
                    return False  # Explicit rejection
                elif code in {450, 451}:
                    logger.debug(f"Email '{email}' has a temporary failure (code {code}) with {mx_host}.")
                    return "TEMPORARY_FAILURE"
            except (smtplib.SMTPConnectError, socket.error) as e:
                logger.warning(f"Error verifying email {email} with {mx_host}: {e}")
                return None
            except Exception as e:
                logger.error(f"Error verifying email {email} with {mx_host}: {e}")
                return None

        logger.debug(f"SMTP verification failed for email '{email}'.")
        return None
    except dns.resolver.NoAnswer:
        logger.warning(f"No MX records found for domain '{domain}'.")
        return None
    except Exception as e:
        logger.error(f"Error verifying email '{email}': {e}")
        return None

# Categorize email
def categorize_email(email_entry, disposable_domains, logger):
    email = email_entry["email"]
    email_id = email_entry["id"]

    logger.info(f"Processing Email ID {email_id}: {email}")

    if not validate_syntax(email, logger):
        logger.info(f"Email ID {email_id} is invalid due to syntax error.")
        return {"id": email_id, "email": email, "status": "invalid", "response": "Syntax error", "score":0}

    domain = email.split('@')[-1]

    if not check_domain(domain, logger):
        logger.info(f"Email ID {email_id} is invalid because domain '{domain}' does not exist.")
        return {"id": email_id, "email": email, "status": "invalid", "response": "Domain doesn't exist", "score":0}

    if is_disposable(domain, disposable_domains, logger):
        logger.info(f"Email ID {email_id} is disposable.")
        return {"id": email_id, "email": email, "status": "Disposable Account", "response": "Email is disposable", "score":0}

    accept_all_status = is_accept_all(domain, logger)
    if accept_all_status is True:
        logger.info(f"Email ID {email_id} belongs to a catch-all domain.")
        return {"id": email_id, "email": email, "status": "catch all", "response": "Accept All Domain", "score":0}
    elif accept_all_status is None:
        logger.warning(f"Could not determine if domain '{domain}' is accept-all for Email ID {email_id}.")

    smtp_result = verify_email(email, logger)
    if smtp_result == "TEMPORARY_FAILURE":
        logger.info(f"Email ID {email_id} is temporarily valid.")
        return {"id": email_id, "email": email, "status": "Valid", "response": "Temporary failure detected", "score":1}
    elif smtp_result is None:
        logger.info(f"SMTP verification failed for Email ID {email_id}.")
        return {"id": email_id, "email": email, "status": "unknown", "response": "SMTP verification failed", "score":0}
    elif smtp_result:
        logger.info(f"Email ID {email_id} is valid.")
        return {"id": email_id, "email": email, "status": "Valid", "response": "success", "score":1 }
    else:
        logger.info(f"Email ID {email_id} was rejected by the server.")
        return {"id": email_id, "email": email, "status": "invalid", "response": "Rejected by server", "score":0 }

# Process emails in parallel
def process_emails_parallel(email_entries, disposable_domains, db_connection, logger):
    with ThreadPoolExecutor(max_workers=50) as executor:
        future_to_email = {
            executor.submit(categorize_email, email_entry, disposable_domains, logger): email_entry 
            for email_entry in email_entries
        }
        for future in as_completed(future_to_email):
            email_entry = future_to_email[future]
            try:
                result = future.result()

                # Log result using logger
                logger.info(
                    f"ID: {result['id']}, Email: {result['email']}, Status: {result['status']}, "
                    f"Response: {result['response']}, Score: {result['score']}"
                )

                # Update the DB
                update_email_status_in_db(db_connection, result, logger)

            except Exception as e:
                error_result = {
                    "id": email_entry["id"], 
                    "email": email_entry["email"], 
                    "status": f"Error ({e})",
                    "response": str(e),
                    "score": 0
                }

                # Log error using logger
                logger.error(
                    f"ID: {error_result['id']}, Email: {error_result['email']}, "
                    f"Status: {error_result['status']}"
                )

                # Update database with error status
                update_email_status_in_db(db_connection, error_result, logger)

# Update email status in the database
def update_email_status_in_db(db_connection, result, logger):
    try:
        cursor = db_connection.cursor()
        update_query = """
            UPDATE email_lists
            SET status = %s,
                response = %s,
                score = %s
            WHERE id = %s;
        """
        cursor.execute(update_query, (result["status"], result["response"], result["score"], result["id"]))
        db_connection.commit()
        logger.debug(f"Updated DB for Email ID {result['id']}.")
    except Exception as e:
        logger.error(f"Error updating database for ID {result['id']}: {e}")
    finally:
        cursor.close()

# Update the status of task to completed when email job is completed
def update_task_status(db_connection: mysql.connector.MySQLConnection, task_id, logger):
    try:
        cursor = db_connection.cursor()
        update_query = """
            UPDATE tasks
            SET status = 'completed'
            WHERE id = %s;
        """
        cursor.execute(update_query, (task_id,))
        db_connection.commit()
        logger.info(f"Task ID {task_id} marked as completed.")
    except Exception as e:
        logger.error(f"Error updating task status for Task ID {task_id}: {e}")
        try:
            cursor = db_connection.cursor()
            update_query = """
                UPDATE tasks
                SET status = 'failed'
                WHERE id = %s;
            """
            cursor.execute(update_query, (task_id,))
            db_connection.commit()
            logger.info(f"Task ID {task_id} marked as failed.")
        except Exception as nested_e:
            logger.error(f"Nested error updating failed task status for Task ID {task_id}: {nested_e}")
    finally:
        cursor.close()

# Function to check if the required number of arguments is passed
def validate_args(args, logger):
    if len(args) < 7:
        logger.error("Missing arguments. You need to provide at least 6 arguments for DB connection.")
        logger.error("Usage: python script.py <host> <user> <password> <database> <json path> <task_id>")
        sys.exit(1)

# Function to safely get an argument, falling back to a default value if not provided
def get_arg(args, index, default_value, logger):
    try:
        return args[index]
    except IndexError:
        logger.warning(f"Argument at position {index} missing. Using default value: {default_value}")
        return default_value

# Main function
def main():
    # Set up logging
    log_file_path = "email_validation_log.txt"
    logger = setup_logging(log_file_path)
    logger.info("Email validation script started.")

    disposable_domains = load_disposable_domains(logger)

    args = sys.argv

    # Validate arguments
    validate_args(args, logger)

    host = get_arg(args, 1, "localhost", logger)
    user = get_arg(args, 2, "root", logger)
    password = get_arg(args, 3, "password", logger)
    database = get_arg(args, 4, "email_lists", logger)
    file_path = get_arg(args, 5, "demo.json", logger)
    task_id = get_arg(args, 6, "1", logger)

    # Connect to database
    try:
        db_connection = mysql.connector.connect(
            host=host,
            user=user,   
            password=password,  
            database=database,
        )
        logger.info("Connected to the database successfully.")
    except mysql.connector.Error as err:
        logger.critical(f"Database connection failed: {err}")
        sys.exit(1)

    try: 
        # Clear logs from the starting 
        # Not necessary as RotatingFileHandler handles log rotation
        # But if you want to clear the log file at the start, uncomment the following line:
        # open(log_file_path, "w").close()
        
        if not os.path.isfile(file_path):
            logger.error(f"JSON file '{file_path}' does not exist.")
            sys.exit(1)

        with open(file_path, "r") as file:
            emails_entries = json.load(file)
            logger.info(f"Loaded {len(emails_entries)} email entries from '{file_path}'.")

        # Process emails and log/updates in real time
        process_emails_parallel(emails_entries, disposable_domains, db_connection, logger)

    except Exception as e:
        logger.error(f"An error occurred during processing: {e}")
    
    finally:
        if db_connection.is_connected():
            update_task_status(db_connection, task_id, logger)
            db_connection.close()
            logger.info("Database connection closed.")
    
    logger.info("Email validation script finished.")

if __name__ == "__main__":
    main()
