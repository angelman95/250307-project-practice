import sqlite3

# define names
database_name = "testcustomerdata.db"


# create or connect to database
conn = sqlite3.connect(database_name)
conn.row_factory = sqlite3.Row
cursor = conn.cursor()

user_id = 2

# fetch single row
cursor.execute("SELECT * FROM customers WHERE id = ?", (user_id,))
user = cursor.fetchone()

# ensures user exists before accessing database
if user:
    date = input('Enter date in YYYY-MM-DD')
    time = input('Enter time in HH:MM:')

    # here i needed to do conn.row_factory = sqlite3.Row so that i could access rows by name or something
    address = user['address']

    print(f"Date: {date}, Time: {time}")
    print(f"Address: {address}")


conn.commit()
conn.close()
