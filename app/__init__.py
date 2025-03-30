from flask import Flask
from .extensions import mongo

def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')
    
    mongo.init_app(app)

    # Import blueprints here (after app is created)
    from .auth import bp as auth_bp
    from .admin import bp as admin_bp
    from .iperf import iperf_bp
    from .ssh import ssh_bp


    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(iperf_bp)
    app.register_blueprint(ssh_bp)


    return app