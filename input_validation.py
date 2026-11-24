"""Strict validation for the monitoring form. No network requests or logging of values."""
import re
from safe_pii import valid_ssn, valid_sin
from detectors.pii_detector import luhn_check

EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+\Z")
DOMAIN = re.compile(r"(?=.{1,253}\Z)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\Z")
CARD = re.compile(r"\d{13,19}|\d{4}(?:[ -]\d{4}){2,3}(?:[ -]\d{1,3})?\Z")
PHONE = re.compile(r"\+?\d[\d ()-]*\d\Z")
SSN = re.compile(r"\d{3}-?\d{2}-?\d{4}\Z")
SIN = re.compile(r"\d{3}[ -]?\d{3}[ -]?\d{3}\Z")


def validate_monitor_value(kind, value):
    """Return (normalized_value, error_message). Never include input in errors."""
    value = value.strip()
    if not value:
        return None, 'Enter a value to monitor.'
    if kind == 'email':
        return (value.lower(), None) if EMAIL.fullmatch(value) and len(value) <= 254 else (None, 'Enter a valid email address, such as name@example.com.')
    if kind == 'domain':
        return (value.lower(), None) if DOMAIN.fullmatch(value) else (None, 'Enter a valid domain, such as example.com (without https:// or paths).')
    if kind == 'phone':
        digits = re.sub(r'\D', '', value)
        if not PHONE.fullmatch(value) or not 7 <= len(digits) <= 15:
            return None, 'Enter a valid phone number with 7 to 15 digits. Include the country code when possible.'
        # Avoid mistakenly accepting an obvious payment card as a phone number.
        if len(digits) >= 13 and luhn_check(digits):
            return None, 'This looks like a credit card number. Select Credit Card instead.'
        return ('+' + digits if value.startswith('+') else digits), None
    if kind == 'credit_card':
        digits = re.sub(r'[ -]', '', value)
        if not CARD.fullmatch(value) or not 13 <= len(digits) <= 19 or not luhn_check(digits):
            return None, 'Enter a valid test card number (13–19 digits) that passes the Luhn check.'
        return digits, None
    if kind == 'ssn':
        if not SSN.fullmatch(value):
            return None, 'Enter a US SSN as 9 digits or XXX-XX-XXXX.'
        digits = re.sub(r'\D', '', value)
        if not valid_ssn(f'{digits[:3]}-{digits[3:5]}-{digits[5:]}'):
            return None, 'The US SSN does not pass format validation.'
        return digits, None
    if kind == 'sin':
        if not SIN.fullmatch(value) or not valid_sin(value):
            return None, 'Enter a Canadian SIN with 9 digits that passes the checksum.'
        return re.sub(r'\D', '', value), None
    if kind == 'password':
        return value, None
    return None, 'Choose a supported information type.'
