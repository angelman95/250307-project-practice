
import secrets
import sqlite3
import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
import bcrypt
from validation_functions import is_valid_email, is_valid_password, is_valid_phone

app = Flask(__name__)

# cookie security
secret_key = secrets.token_hex(16)
app.secret_key = secret_key

app.config['SESSION_COOKIE_SECURE'] = True  # Send cookies over HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection


# function to hash inputted password
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


def check_password(password, stored_hash):
    # Check if the input password matches the stored hash
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash)


# connects to database
def get_database_connection():
    # use app.instance_path to make path to database folder (very secure probably)
    db_path = os.path.join(app.instance_path, 'customerdata.db')

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # accesses rows by column name
    return conn

    #   how to use:
    #     conn = get_database_connection()
    #     cursor = conn.cursor()
    #     cursor.execute('SELECT * FROM customers') <- query goes here


# passing session data
@app.context_processor
def inject_user():
    user_id = session.get('user_id')
    return dict(user_id=user_id)


# landing page
@app.route('/')
def index():
    return redirect(url_for('home'))


# home page
@app.route('/home')
def home():
    return render_template('home.html')


# login page
@app.route('/login', methods=['GET'])
def login_page():
    return render_template('login.html')


# login logic
@app.route('/login', methods=['POST'])
def login():
    # gets input data from html
    email = request.form['email']
    password = request.form['password']

    # connect to database
    conn = get_database_connection()
    cursor = conn.cursor()

    # check if the email exists in database
    cursor.execute('SELECT * FROM customers WHERE email = ?', (email,))
    user = cursor.fetchone()



    if user:
        print("Email found")

        try:
            if check_password(password, user['password']):  # if hashed passwords match
                session['user_id'] = user['customer_id']  # store user id in session

                print("Successful login!")
                print("Logged in as ", user['customer_id'])


                conn.close()
                return redirect(url_for('home'))  # redirects after successful login

            else:  # if the email or passwords do not match
                flash("Invalid credentials")
                print("invalid credentials")
                conn.close()
                return redirect(url_for('login'))  # redirect to login page
        except:
            flash("We are having problems on our side. Please try again later.")
            print("Database is not connected")
            return redirect(url_for('login'))

    else:
        print("Email not found")
        flash("Invalid credentials")
        return redirect(url_for('login'))

# logout button
@app.route('/logout')
def logout():
    session.pop('user_id', None)  # remove cookie
    return redirect(url_for('login'))


# register page
@app.route('/register', methods=['GET'])
def register_page():
    return render_template('register.html')


# register logic
@app.route('/register', methods=['POST'])
def register():
    first_name = request.form.get('first_name', None)
    last_name = request.form.get('last_name', None)
    email = request.form.get('email', None)
    city = request.form.get('city', None)
    address = request.form.get('address', None)
    postcode = request.form.get('postcode', None)
    phone = request.form.get('phone', None)
    password = request.form.get('password', None)

    # validation
    # Check if all fields are filled
    if not all([first_name, last_name, email, city, address, postcode, phone, password]):
        print("All fields are required.")
        return render_template('register.html',
                               first_name=first_name, last_name=last_name, email=email,
                               city=city, address=address, postcode=postcode,
                               phone=phone)

    # Validate email format
    if not is_valid_email(email):
        print("Invalid email format.")
        return render_template('register.html',
                               first_name=first_name, last_name=last_name, email=email,
                               city=city, address=address, postcode=postcode,
                               phone=phone)

    # Validate phone number
    if not is_valid_phone(phone):
        print("Invalid phone number.")
        return render_template('register.html',
                               first_name=first_name, last_name=last_name, email=email,
                               city=city, address=address, postcode=postcode,
                               phone=phone)

    # Validate password length
    if not is_valid_password(password):
        print("Password must contain at least 8 characters and a number.")
        return render_template('register.html',
                               first_name=first_name, last_name=last_name, email=email,
                               city=city, address=address, postcode=postcode,
                               phone=phone)

    # hash password
    hashed_password = hash_password(password)

    # check if phone and email already exists
    with get_database_connection() as conn:
        email_exists = \
            conn.execute('SELECT EXISTS(SELECT 1 FROM customers WHERE email = ?);', (email,)).fetchone()[0]
        phone_exists = \
            conn.execute('SELECT EXISTS(SELECT 1 FROM customers WHERE phone = ?);', (phone,)).fetchone()[0]

    # if email or phone is already in database
    if email_exists or phone_exists:
        print("Email or phone number is already associated with an account.")
        return redirect(url_for('register'))

    else:
        print("Creating new customer")

        # connect to database
        conn = get_database_connection()
        # add information to database
        conn.execute('''
            INSERT INTO customers (forename, surname, email, city, address, postcode, phone, password)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
        ''', (first_name, last_name, email, city, address, postcode, phone, hashed_password))
        conn.commit()
        conn.close()

        return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
