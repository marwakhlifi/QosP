from flask import Flask
from .extensions import mongo, mail
import logging


def create_app():
    app = Flask(__name__)
    app.config.from_object('config.Config')

    mongo.init_app(app)
    mail.init_app(app)

    logging.basicConfig(level=logging.DEBUG)
    app.logger.setLevel(logging.DEBUG)

    from .auth.routes import auth_bp  
    from .iperf import iperf_bp
    from .ssh import ssh_bp
    from .auto import bp as auto_bp
    from .ping import ping_bp  
    from .traceroute import traceroute_bp
    from .nslookup import nslookup_bp
    from .qoscheck import qos_bp
    from .validation import validation_bp
    from .telnet import telnet_bp
    from .control import control_bp

 
    


    app.register_blueprint(auth_bp, url_prefix='/')

    app.register_blueprint(iperf_bp)
    app.register_blueprint(ssh_bp)
    app.register_blueprint(auto_bp)
    app.register_blueprint(ping_bp)
    app.register_blueprint(traceroute_bp)
    app.register_blueprint(nslookup_bp)
    app.register_blueprint(qos_bp)
    app.register_blueprint(validation_bp)
    app.register_blueprint(telnet_bp)
    app.register_blueprint(control_bp)
    





    return app
