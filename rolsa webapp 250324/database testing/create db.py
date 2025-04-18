import sqlite3

database_name = "customerdata.db"

# create or connect to database
conn = sqlite3.connect(database_name)
cursor = conn.cursor()


# create table if not exists
cursor.execute('''
       CREATE TABLE IF NOT EXISTS customers (
            customer_id INTEGER PRIMARY KEY AUTOINCREMENT,
            forename TEXT,
            surname TEXT,
            email TEXT,
            city TEXT,
            address TEXT,
            postcode TEXT,
            phone TEXT,
            password TEXT
        )
    ''')


# create booking table if not exists
cursor.execute('''
       CREATE TABLE IF NOT EXISTS bookings (
            booking_id INTEGER PRIMARY KEY AUTOINCREMENT,
            date DATE,
            time TIME,
            address TEXT,
            postcode TEXT,
            customer_id INTEGER,
            FOREIGN KEY(customer_id) REFERENCES customers(customer_id)
        )
    ''')

conn.commit()
conn.close()
