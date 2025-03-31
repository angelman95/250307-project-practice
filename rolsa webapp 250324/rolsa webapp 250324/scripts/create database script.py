import csv
import sqlite3

# define names
database_name = "customerdata.db"
table_name = "customers"

# create or connect to database
conn = sqlite3.connect(database_name)
cursor = conn.cursor()

# create table if not exists
cursor.execute(f'''
       CREATE TABLE IF NOT EXISTS {table_name} (
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

def add_csv_data():
    # path to csv
    csv_file = '../static/csv/customers.csv'

    # open the csv file and import data
    with open(csv_file, 'r') as file:
        csv_reader = csv.reader(file)
        header = next(csv_reader) # skip header

        # insert each row from csv into database
        for row in csv_reader:
            cursor.execute(f'''
                INSERT INTO {table_name} (forename, surname, email, city, address, postcode, phone, password)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            
            ''', row)


conn.commit()
conn.close()
