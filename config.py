import os

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'fdf3b077e67f77d9b75322212cd0d50f8932ed96db890458caaeab3aa27c2f44')
    SQLALCHEMY_DATABASE_URI = os.getenv('SQLALCHEMY_DATABASE_URI', 'mysql+pymysql://Team12:paSsword@cpsc4910-f25.cobd8enwsupz.us-east-1.rds.amazonaws.com/Team12_DB')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = os.getenv('MAIL_USERNAME')
    MAIL_PASSWORD = os.getenv('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = ("Triple T's Rewards", os.getenv('MAIL_USERNAME'))
