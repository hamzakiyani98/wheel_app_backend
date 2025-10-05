import pymysql
from config import Config

def get_db():
    try:
        return pymysql.connect(
            host=Config.MYSQL_HOST,
            user=Config.MYSQL_USER,
            password=Config.MYSQL_PASSWORD,
            database=Config.MYSQL_DB
        )
    except pymysql.MySQLError as err:
        print(f"Error: {err}")
        return None
