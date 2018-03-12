import string
import re

from ckan import authz
from ckan.common import _
from ckan.lib.navl.dictization_functions import Missing, Invalid


MIN_PASSWORD_LENGTH = 10
MIN_LEN_ERROR = (
    'Your password must be {} characters or longer, and consist of at least '
    'three of the following character sets: uppercase characters, lowercase '
    'characters, digits, punctuation & special characters.'
)


def user_password_validator(key, data, errors, context):
    value = data[key]

    if isinstance(value, Missing):
        pass  # Already handeled in core
    elif not isinstance(value, basestring):
        raise Invalid(_('Passwords must be strings.'))
    elif value == '':
        pass  # Already handeled in core
    else:
        # NZISM compliant password rules
        rules = [
            any(x.isupper() for x in value),
            any(x.islower() for x in value),
            any(x.isdigit() for x in value),
            any(x in string.punctuation for x in value)
        ]
        if len(value) < MIN_PASSWORD_LENGTH or sum(rules) < 3:
            raise Invalid(_(MIN_LEN_ERROR.format(MIN_PASSWORD_LENGTH)))


def old_username_validator(key, data, errors, context):
    # Completely prevents changing of user names
    old_user = authz._get_user(context.get('user'))
    return old_user.name

def user_name_sanitize(key, data, errors, context):
    value = data[key]
    if is_input_valid(value) is False:
        raise Invalid(_('Input Contains Malicious Data'))
    else:
        pass

def user_about_validator(key, data, errors, context):
    value = data[key]
    if is_input_valid(value) is False:
        raise Invalid(_('Input Contains Malicious Data'))
    else:
        pass

def is_input_valid(input_value):
    invalid_list = ['hacked', 'hack[^a-zA-Z]+by']
    for invalid_string in invalid_list:
        if re.search(invalid_string, input_value.lower()):
            return False
    return True
