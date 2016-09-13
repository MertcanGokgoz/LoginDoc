import sqlite3
import sys

try:
    db = sqlite3.connect('/home/mertcan/PycharmProjects/Login/logindoc.db', check_same_thread=False)
    cursor = db.cursor()
    cursor.execute("DROP TABLE IF EXISTS logindoc")
    sql = """CREATE TABLE logindoc ( id INTEGER PRIMARY KEY AUTOINCREMENT, title text NOT NULL, description text NOT NULL, url text NOT NULL )"""
    cursor.execute(sql)
    db.close()
    print("Database and Table Created")
except Exception as e:
    print("\n[ Error ]\n\t Error Message:\t ", e, "\n")
sys.exit(1)
