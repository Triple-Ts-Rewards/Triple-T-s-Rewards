import os
import random
import string
import hashlib
from datetime import datetime, timedelta
from flask import current_app
from flask_mail import Message
from extensions import db, mail
from models import Email2FACode  # this model from your earlier step

# -------------------------------
# Generate and store an email 2FA code
# -------------------------------
def create_email_code(user, purpose="login"):
    # make a random 6-digit code
    code = "".join(random.choices(string.digits, k=6))

    # hash the code before storing
    code_hash = hashlib.sha256(code.encode()).hexdigest()

    expires = datetime.utcnow() + timedelta(minutes=10)

    # create row
    entry = Email2FACode(
        user_id=user.USER_CODE,
        purpose=purpose,
        code_hash=code_hash,
        expires_at=expires
    )
    db.session.add(entry)
    db.session.commit()

    return code  # plain code returned so you can email it


# -------------------------------
# Verify user-entered code
# -------------------------------
def verify_email_code(user, code_entered, purpose="login"):
    code_hash = hashlib.sha256(code_entered.encode()).hexdigest()

    code_row = (
        Email2FACode.query
        .filter_by(user_id=user.USER_CODE, purpose=purpose, consumed_at=None)
        .order_by(Email2FACode.sent_at.desc())
        .first()
    )
    if not code_row:
        return False

    if code_row.expires_at < datetime.utcnow():
        return False

    if code_row.code_hash != code_hash:
        code_row.attempts += 1
        db.session.commit()
        return False

    code_row.consumed_at = datetime.utcnow()
    db.session.commit()
    return True

def send_email(to, subject, body):
    print(f"\n=== EMAIL 2FA SIMULATION ===")
    print(f"To: {to}")
    print(f"Subject: {subject}")
    print(f"Body:\n{body}")
    print(f"=============================\n")

# -------------------------------
# Send email (requires Flask-Mail)
# -------------------------------
#def send_email(to_address, subject, body):
#   msg = Message(
#     sender=os.getenv("SMTP_FROM") or "no-reply@example.com",
#        recipients=[to_address],
#       body=body
#   )
#   mail.send(msg)
#   current_app.logger.info(f"Sent 2FA email to {to_address}")

