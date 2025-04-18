from app import get_database_connection
import sqlite3

# make sure to move this file to same directory as app.py before using

conn = get_database_connection()
cur = conn.cursor()

while True:
    customer_id = input("Enter customer ID to delete: ")

    query = f"DELETE FROM customers WHERE customer_id = {customer_id}"
    cur.execute(query)
    conn.commit()

    if cur.rowcount > 0:
        print("Customer ID deleted")
    else:
        print("Customer ID does not exist")





