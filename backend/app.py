import logging

from flask import Flask, jsonify
from flask_cors import CORS

from backend.config import Config
from backend.routes.scan_routes import scan_bp


def create_app(config_object=Config):
    app = Flask(__name__)
    app.config.from_object(config_object)

    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": app.config["CORS_ORIGINS"],
                "methods": ["GET", "POST", "OPTIONS"],
                "allow_headers": ["Content-Type"],
            }
        },
    )

    @app.route("/api/health", methods=["GET"])
    def health_check():
        return jsonify({
            "status": "success",
            "message": "CAST API is running.",
            "service": "CAST Backend",
        }), 200

    @app.errorhandler(404)
    def not_found(_error):
        return jsonify({
            "status": "error",
            "message": "API route not found.",
        }), 404

    @app.errorhandler(500)
    def internal_error(error):
        logging.getLogger(__name__).exception(
            "Unhandled CAST API error: %s", error
        )
        return jsonify({
            "status": "error",
            "message": "An internal server error occurred.",
        }), 500

    app.register_blueprint(scan_bp, url_prefix="/api")
    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=app.config["DEBUG"],
    )
