import csv
import sqlite3

# define names
database_name = "customerdata.db"


# create or connect to database
conn = sqlite3.connect(database_name)
cursor = conn.cursor()


# create table if not exists
def create_user_table():
    table_name = "customers"

    cursor.execute(f'''
           CREATE TABLE IF NOT EXISTS {table_name} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    table_name = "customers"
    # path to csv
    csv_file = '../static/csv/customers.csv'

    # open the csv file and import data
    with open(csv_file, 'r') as file:
        csv_reader = csv.reader(file)
        header = next(csv_reader)  # skip header

        # insert each row from csv into database
        for row in csv_reader:
            cursor.execute(f'''
                INSERT INTO {table_name} (forename, surname, email, city, address, postcode, phone, password)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)

            ''', row)


def create_booking_database():
    table_name = "bookings"
    cursor.execute(f'''
               CREATE TABLE IF NOT EXISTS {table_name} (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    date TEXT NOT NULL,
                    time TEXT NOT NULL,
                    address TEXT NOT NULL,
                    postcode TEXT NOT NULL,
                    user_id INTEGER NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES customers(id)
                )
            ''')


def insert_example_data():
    table_name = "customers"

    # Example data
    example_data = [
        ('John', 'Doe', 'john.doe@example.com', 'New York', '123 Elm St', '10001', '123-456-7890', 'password123'),
        ('Jane', 'Smith', 'jane.smith@example.com', 'Los Angeles', '456 Oak St', '90001', '987-654-3210',
         'securepassword456'),
        ('Alice', 'Johnson', 'alice.johnson@example.com', 'Chicago', '789 Pine St', '60601', '555-123-4567',
         'alicepassword789')
    ]

    # Insert the example data into the table
    cursor.executemany(f'''
        INSERT INTO {table_name} (forename, surname, email, city, address, postcode, phone, password)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', example_data)


create_booking_database()

conn.commit()
conn.close()
