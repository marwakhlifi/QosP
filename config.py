# app/config.py
from pathlib import Path
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY')
    TEMPLATES_AUTO_RELOAD = True
    
    MONGO_URI = 'mongodb://localhost:27017/UserDB'
    
    IPERF_PATH = r"C:\Users\marou\Downloads\iperf3\iperf-3.1.3-win64\iperf3.exe"
    GRAPH_FOLDER = os.path.join(Path(__file__).parent.parent, 'app', 'static', 'graphs')
    
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True 
    MAIL_USE_SSL = False  
    MAIL_USERNAME = 'maroukhlifi15@gmail.com'
    MAIL_PASSWORD = 'aaggayhzbadgxar'  # App Password
    MAIL_DEFAULT_SENDER = 'maroukhlifi15@gmail.com'