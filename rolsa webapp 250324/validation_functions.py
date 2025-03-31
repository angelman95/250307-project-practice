import re


# ensure email follows format "example@domain.com"
def is_valid_email(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email)


# validate UK phone numbers
def is_valid_phone(phone):

    # if the phone number contains only digits and has 11 characters
    if not phone.isdigit() or len(phone) != 11:
        return False

    # Validate UK phone number prefixes
    uk_phone_regex = r'^(07\d{9}|01\d{10}|02\d{10}|03\d{10}|08\d{10})$'

    # Match the phone number with the regex for valid UK numbers
    return re.match(uk_phone_regex, phone) is not None


# creates password ruleset
def is_valid_password(password):
    # Check password length (e.g., minimum 8 characters)
    if len(password) < 8:
        return False

    # Check for at least one number
    if not re.search(r'\d', password):
        return False

    return True