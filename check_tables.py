from app import db, app
from sqlalchemy import text

with app.app_context():
    # Connect to the database
    conn = db.engine.connect()
    result = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table';"))
    tables = [row[0] for row in result]
    conn.close()

print("Tables in the database:", tables)
