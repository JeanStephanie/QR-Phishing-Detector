"""Route registration — imports all route modules to attach handlers to blueprints."""

from routes.blueprints import main_bp, api_bp

import routes.auth  # noqa: F401
import routes.scan  # noqa: F401
import routes.dashboard  # noqa: F401
import routes.admin  # noqa: F401
import routes.api  # noqa: F401

__all__ = ["main_bp", "api_bp"]
