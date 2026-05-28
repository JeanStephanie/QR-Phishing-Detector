import os
from flask import Flask
from config import Config
from routes.main import main_bp
from routes.api import api_bp


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp)

    @app.context_processor
    def inject_globals():
        from flask import session
        return {
            "app_name": "SafeNet QR Shield",
            "user_email": session.get("user_email"),
            "is_logged_in": session.get("logged_in", False),
        }

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
