from flask import Flask
from flask_cors import CORS

from config import Config
from extensions import db, migrate, bcrypt, jwt


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # Allow requests from both React dev servers
    CORS(app, origins=["http://localhost:3000", "http://localhost:4000"],
         supports_credentials=True)

    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)
    jwt.init_app(app)

    # Register routes blueprint
    from routes import bp
    app.register_blueprint(bp)

    @app.route("/")
    def home():
        return {"message": "Productivity API running successfully!"}, 200

    return app


app = create_app()

if __name__ == "__main__":
    app.run(debug=True)
