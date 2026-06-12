from functools import wraps

from flask import request
from flask_wtf.csrf import CSRFProtect


def exempt_routes_from_csrf(csrf_protect: CSRFProtect, routes):
    """Exempt specific view functions from CSRF (unchanged frontend forms/APIs)."""
    for view_func in routes:
        csrf_protect.exempt(view_func)


def csrf_exempt(f):
    """Decorator placeholder; actual exemption applied during app init."""
    f._csrf_exempt = True
    return f
