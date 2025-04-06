from flask import Flask
from .extensions import mongo
from flask_mail import Mail

mail = Mail()

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    # Initialize extensions
    mongo.init_app(app)
    mail.init_app(app)

    # Import and register blueprints
    from .auth import bp as auth_bp
    from .admin import bp as admin_bp
    from .iperf import iperf_bp
    from .ssh import ssh_bp
    from .auto import bp as auto_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(iperf_bp)
    app.register_blueprint(ssh_bp)
    app.register_blueprint(auto_bp)  # This registers the auto blueprint

    return app