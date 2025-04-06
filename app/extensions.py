from flask_pymongo import PyMongo
from flask_mail import Mail


mongo = PyMongo()
mail = Mail()

def init_db(app):
    app.config['MONGO_URI'] = 'mongodb://localhost:27017/UserDB'
    mongo.init_app(app)


