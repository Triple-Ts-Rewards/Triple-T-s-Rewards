from extensions import db
from models import AuditLog
import logging
from datetime import datetime

#Event Type Conventions
SALES_BY_SPONSOR = "SALES_BY_SPONSOR"
SALES_BY_DRIVER  = "SALES_BY_DRIVER"
INVOICE_EVENT    = "INVOICE_EVENT"
DRIVER_POINTS    = "DRIVER_POINTS"
LOGIN_EVENT    = "LOGIN_EVENT"
DRIVER_DROPPED   = "DRIVER_DROPPED"

ACCOUNT_DISABLED = "ACCOUNT_DISABLED"
ACCOUNT_ENABLED  = "ACCOUNT_ENABLED"
ADMIN_TIMEOUT_EVENT = "ADMIN_TIMEOUT"
ADMIN_CLEAR_TIMEOUT = "ADMIN_CLEAR_TIMEOUT"
ACCOUNT_UNLOCKED = "ACCOUNT_UNLOCKED"
ACCOUNT_UNLOCKED_ALL = "ACCOUNT_UNLOCKED_ALL"


logging.basicConfig(level=logging.INFO)

def log_audit_event(event_type: str, details: str = ""):
    log_entry = AuditLog(
        EVENT_TYPE=event_type,
        DETAILS=details or None,
        CREATED_AT=datetime.utcnow()
    )
    db.session.add(log_entry)
    db.session.commit()
    logging.info("AUDIT: %s - %s", event_type, details)
    return log_entry

def log_driver_dropped(*, sponsor_id:int, org_id:int, driver_id:int):
    """
    Audit entry for when a sponsor drops a driver from an org.
    """
    details = f"sponsor={sponsor_id} org={org_id} driver={driver_id}"
    return log_audit_event(DRIVER_DROPPED, details)
