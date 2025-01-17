import re
import smtplib
import dns.resolver

def validate_email_syntax(email):
    """Validates the syntax of an email."""
    regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(regex, email) is not None

def get_mx_records(domain):
    """Fetches MX records for a domain."""
    try:
        mx_records = dns.resolver.resolve(domain, 'MX')
        return [str(record.exchange).strip('.') for record in mx_records]
    except Exception as e:
        return []

def smtp_check(email, mx_records):
    """Performs an SMTP check for the email."""
    try:
        # Extract domain
        domain = email.split('@')[1]
        
        # Connect to the first MX server
        mx_server = mx_records[0]
        with smtplib.SMTP(mx_server) as smtp:
            smtp.helo()
            smtp.mail('test@example.com')  # Dummy sender email
            response, _ = smtp.rcpt(email)  # Test recipient email
            if 200 <= response < 300:
                return "Valid"
            elif 400 <= response < 500:
                return "Invalid"
            else:
                return "Unknown"
    except Exception as e:
        return "Unknown"

def check_catch_all(mx_records):
    """Checks if the domain is a catch-all."""
    try:
        test_email = f'test-{hash(mx_records)}@{mx_records[0]}'
        with smtplib.SMTP(mx_records[0]) as smtp:
            smtp.helo()
            smtp.mail('test@example.com')  # Dummy sender email
            response, _ = smtp.rcpt(test_email)  # Test with a non-existent email
            if 200 <= response < 300:
                return True
    except Exception:
        pass
    return False

def validate_email(email):
    """Validates a single email address."""
    # Step 1: Validate Syntax
    if not validate_email_syntax(email):
        return "Invalid Syntax"

    # Step 2: Validate Domain
    domain = email.split('@')[1]
    mx_records = get_mx_records(domain)
    if not mx_records:
        return "Invalid Domain"

    # Step 3: Check Catch-All Domain
    if check_catch_all(mx_records):
        return "Catch-All Domain"

    # Step 4: Perform SMTP Validation
    status = smtp_check(email, mx_records)
    return status

def validate_emails(emails):
    """Validates a list of emails and returns statuses."""
    results = {}
    for email in emails:
        results[email] = validate_email(email)
    return results

if __name__ == "__main__":
    # Input: List of emails
    emails_to_validate = [
        "transport@backmarket.com",
        "companyinfo@mail.bankrate.com",
        "webmaster@bankrate.com",
        "webmaster@mail.bankrate.com",
        "feedback@mybankrate.com",
        "legal@bankrate.com",
        "customersupport@bankrate.com",
        "team@bark.com",
        "contact@bark.com"
    ]

    # Validate emails
    statuses = validate_emails(emails_to_validate)

    # Print results
    for email, status in statuses.items():
        print(f"{email}: {status}")
