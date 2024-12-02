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
        conn.execute('''
            CREATE TABLE IF NOT EXISTS blood_oxygen_levels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                blood_oxygen_level REAL NOT NULL,
                date TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        conn.commit()
        conn.execute('''
            CREATE TABLE blood_pressure (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            blood_pressure TEXT NOT NULL,
            date TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        conn.commit()

        


if __name__ == '__main__':
    init_db()
    print("Database initialized successfully.")