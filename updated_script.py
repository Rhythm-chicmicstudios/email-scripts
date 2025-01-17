import smtplib
import dns.resolver
import socket
import logging

# Setup logger
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Constants for response codes
VALID_CODES = {250, 251}  # Valid email codes
INVALID_CODES = {550, 553}  # Invalid email codes
TEMPORARY_FAILURE_CODES = {450, 451, 452}  # Temporary failure codes

# Perform SMTP verification for email
def verify_email(email):
    domain = email.split('@')[-1]

    try:
        # Resolve MX records for the domain
        mx_records = dns.resolver.resolve(domain, 'MX', lifetime=20)
        mx_records = sorted(mx_records, key=lambda x: x.preference)
        logger.debug(f"MX records for domain '{domain}': {[mx.exchange for mx in mx_records]}")

        # Initialize final result
        final_status = None

        # Try each MX record
        for mx in mx_records:
            mx_host = str(mx.exchange)
            try:
                # Connect to the mail server
                server = smtplib.SMTP(mx_host, timeout=10)
                server.set_debuglevel(0)  # Disable debug output from SMTP server
                server.helo()

                # Send MAIL command
                server.mail("rakumar@timesrecordnews.com")

                # Send RCPT command to check email
                code, _ = server.rcpt(email)
                server.quit()

                # Check the response codes
                if code in VALID_CODES:
                    logger.debug(f"Email '{email}' is valid (accepted by {mx_host}).")
                    final_status = True  # Email is valid
                    break
                elif code in INVALID_CODES:
                    logger.debug(f"Email '{email}' is invalid (rejected by {mx_host} with code {code}).")
                    final_status = False  # Email is invalid
                    break
                elif code in TEMPORARY_FAILURE_CODES:
                    logger.debug(f"Email '{email}' has a temporary failure (code {code}) with {mx_host}.")
                    final_status = "TEMPORARY_FAILURE"  # Temporary failure
                    break
                else:
                    logger.debug(f"Email '{email}' has an unknown response code {code} from {mx_host}.")
                    final_status = False  # Unknown error, consider invalid
                    break

            except (smtplib.SMTPConnectError, socket.error) as e:
                logger.warning(f"Error connecting to mail server '{mx_host}' for email '{email}': {e}")
                final_status = None
            except Exception as e:
                logger.error(f"Error verifying email '{email}' with {mx_host}: {e}")
                final_status = None

            # If final status is determined, break out of the loop
            if final_status is not None:
                break

        # Final result after checking all MX records
        if final_status is None:
            logger.debug(f"Unable to verify email '{email}'.")
        return final_status

    except dns.resolver.NoAnswer:
        logger.warning(f"No MX records found for domain '{domain}'.")
        return None
    except Exception as e:
        logger.error(f"Error verifying email '{email}': {e}")
        return None

# Test the function
if __name__ == "__main__":
    email_to_verify = "meloni.cox@timesrecordnews.com"
    status = verify_email(email_to_verify)
    print(f"Final verification status for '{email_to_verify}': {status}")
