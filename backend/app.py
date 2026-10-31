
from flask import Flask, jsonify
from flask_cors import CORS

from backend.routes.scan_routes import scan_bp


def create_app():
    app = Flask(__name__)

    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": ["http://localhost:5173"]
            }
        }
    )

    @app.route("/api/health", methods=["GET"])
    def health_check():
        return jsonify({
            "status": "success",
            "message": "Cloud Attack-Surface Decay Tracker API is running",
            "service": "CAST Backend"
        }), 200

    app.register_blueprint(scan_bp, url_prefix="/api")

    return app


app = create_app()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
