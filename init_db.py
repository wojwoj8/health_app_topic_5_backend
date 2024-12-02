import sqlite3

DATABASE = 'users.db'

def init_db():
    """Initialize the database by creating the users table."""
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        conn.commit()

if __name__ == '__main__':
    init_db()
    print("Database initialized successfully.")