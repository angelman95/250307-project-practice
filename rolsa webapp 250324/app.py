import secrets
import sqlite3
import os
import csv
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
import bcrypt
from validation_functions import is_valid_email, is_valid_password, is_valid_phone
from datetime import date, timedelta, datetime

app = Flask(__name__)

# cookie security
secret_key = secrets.token_hex(16)
app.secret_key = secret_key

app.config['SESSION_COOKIE_SECURE'] = True  # send cookies over HTTPS only
app.config['SESSION_COOKIE_HTTPONLY'] = True  # prevent javascript access
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection

# session lifetime
app.permanent_session_lifetime = timedelta(hours=1)

# TEMPORARY
# csv path for products data
products_csv_path = "static/csv/products.csv"

# questions for carbon footprint calculator with score embedded
questions = [
    ("Do you use solar panels at home?", 20),
    ("Do you drive an electric vehicle?", 10),
    ("Do you use smart thermostats or smart home energy management?", 10),
    ("Do you recycle regularly?", 5),
    ("Do you compost food waste?", 5),
    ("Do you minimize single-use plastics?", 5),
    ("Do you buy local/organic food?", 5),
    ("Do you use public transportation or bike instead of driving?", 20),
    ("Do you limit your air travel?", 10),
    ("Do you conserve water with low-flow fixtures or habits?", 10)
]

# hash inputted password
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password


# check if the input password matches the stored hash
def check_password(password, stored_hash):
    return bcrypt.checkpw(password.encode('utf-8'), stored_hash)


# connects to database
def get_database_connection():
    # use app.instance_path to make path to database folder (very secure probably)
    db_path = os.path.join(app.instance_path, 'customerdata.db')

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # accesses rows by column name
    return conn


# TO BE TURNED INTO DATABASE
# reads csv data for product lists
def read_products_csv():
    products = []
    with open("static/csv/products.csv", newline='', encoding='utf-8') as csvfile:
        csvreader = csv.DictReader(csvfile)
        for row in csvreader:
            products.append(row)
    return products

# gets weekdays to exclude weekends when booking
def get_weekdays(start_date, days=14):
    valid_dates = []
    current = start_date
    while len(valid_dates) < days:
        if current.weekday() < 5:  # monday-friday only
            valid_dates.append(current.strftime('%Y-%m-%d'))
        current += timedelta(days=1)
    return valid_dates


# fetch user info
def fetch_user():

    # get user id from session
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))

    # connect to database and fetch user info
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM customers WHERE customer_id = ?", (user_id,))
    user = cursor.fetchone()

    return user


# function to check if user is logged in
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# passing session data
@app.context_processor
def inject_user():
    user_id = session.get('user_id')
    return dict(user_id=user_id)

# delete booking
@app.route('/cancel-booking', methods=['POST'])
@login_required
def cancel_booking():
    user = fetch_user()

    conn = get_database_connection()
    conn.execute('DELETE FROM bookings WHERE customer_id = ?;', (user['customer_id'],))
    conn.commit()
    conn.close()

    return redirect(url_for('profile_page'))


# landing page
@app.route('/')
def index():
    return redirect(url_for('home'))


# home page
@app.route('/home')
def home():
    return render_template('home.html')


# list products page
@app.route('/services')
def services():
    products = read_products_csv()
    return render_template('services.html', products=products)


# product profile, product information passed from csv
@app.route("/product/<int:product_id>")
def product_profile(product_id):
    db = get_database_connection()
    cur = db.execute("SELECT * FROM products WHERE productID = ?", (product_id,))
    product = cur.fetchone()

    if not product:
        return "Product not found", 404

    return render_template('product_profile.html', product=product)


# contact page
@app.route('/contact')
@login_required
def contact():

    email = session.get('email')

    return render_template('contact.html', email=email)


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

                # store user information in session
                session.permanent = True # sets session lifetime
                session['user_id'] = user['customer_id']  # store user id in session
                session['email'] = user['email']


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
@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)  # remove cookie
    session.clear()
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
        flash("All fields are required.")
        return render_template('register.html',
                               first_name=first_name, last_name=last_name, email=email,
                               city=city, address=address, postcode=postcode,
                               phone=phone)

    # Validate email format
    if not is_valid_email(email):
        flash("Invalid email format.")
        return render_template('register.html',
                               first_name=first_name, last_name=last_name, email=email,
                               city=city, address=address, postcode=postcode,
                               phone=phone)

    # Validate phone number
    if not is_valid_phone(phone):
        flash("Invalid phone number.")
        return render_template('register.html',
                               first_name=first_name, last_name=last_name, email=email,
                               city=city, address=address, postcode=postcode,
                               phone=phone)

    # Validate password length
    if not is_valid_password(password):
        flash("Password must contain at least 8 characters and a number.")
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
        flash("Email or phone number is already associated with an account.")
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


# booking page
@app.route('/booking', methods=['GET'])
@login_required
def booking_page():

    selected_date = request.args.get('date')
    selected_time = request.args.get('time')
    available_times = []

    # if no date chosen yet, don't show times
    if selected_date:
        try:
            booking_date = datetime.strptime(selected_date, "%Y-%m-%d").date()
            if booking_date.weekday() < 5:
                conn = get_database_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT time FROM bookings WHERE date = ?", (selected_date,))
                booked_times = [row['time'] for row in cursor.fetchall()]
                conn.close()

                all_times = [f"{hour:02d}:00" for hour in range(9, 18)]
                available_times = [t for t in all_times if t not in booked_times]
        except ValueError:
            selected_date = None  # fallback if bad date

    customer = None
    if selected_date and selected_time:
        user = fetch_user()
        conn = get_database_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT city, address, postcode FROM customers WHERE customer_id = ?", (user['customer_id'],))
        customer = cursor.fetchone()
        conn.close()

    return render_template(
        'booking.html',
        selected_date=selected_date,
        selected_time=selected_time,
        available_times=available_times,
        customer=customer
    )

# booking logic
@app.route('/booking', methods=['POST'])
def booking():

    # get info from form
    date_str = request.form.get('date')
    time_str = request.form.get('time')
    city = request.form.get('city')
    address = request.form.get('address')
    postcode = request.form.get('postcode')

    # validate date is a weekday
    try:
        booking_date = datetime.strptime(date_str, "%Y-%m-%d").date()
        if booking_date.weekday() >= 5:
            return "Bookings are only allowed on weekdays.", 400
    except ValueError:
        return "Invalid date format.", 400

    # validate time is on the hour
    try:
        booking_time = datetime.strptime(time_str, "%H:%M").time()
        if booking_time.minute != 0:
            return "Please choose a time on the hour (e.g., 10:00, 14:00).", 400
    except ValueError:
        return "Invalid time format.", 400

    user = fetch_user()


    # adds booking info to booking table
    conn = get_database_connection()

    # delete existing booking for this customer
    conn.execute('DELETE FROM bookings WHERE customer_id = ?;', (user['customer_id'],))

    # insert the new booking
    conn.execute('''
        INSERT INTO bookings (date, time, city, address, postcode, customer_id)
        VALUES (?, ?, ?, ?, ?, ?);
    ''', (date_str, time_str, city, address, postcode, user['customer_id']))

    conn.commit()
    conn.close()

    return redirect(url_for('booking_confirmation'))


@app.route('/booking_confirmation')
def booking_confirmation():
    ## get database information to display
    user_id = session.get('user_id')
    conn = get_database_connection()
    cursor = conn.cursor()
    # get account information
    cursor.execute("SELECT * FROM customers WHERE customer_id = ?", (user_id,))
    customer = cursor.fetchone()
    # get booking details
    cursor.execute("""
               SELECT booking_id, date, time, city, address, postcode
               FROM bookings
               WHERE customer_id = ?
               ORDER BY date DESC
           """, (user_id,))
    booking_info = cursor.fetchone()

    conn.close()

    if not customer:
        return "User not found", 404

    confirm_cancel = request.args.get('confirm_cancel') == 'True'

    return render_template('booking-confirmation.html', customer=customer, booking=booking_info, confirm_cancel=confirm_cancel)

@app.route('/profile')
@login_required
def profile_page():

    ## get database information to display
    user_id = session.get('user_id')
    conn = get_database_connection()
    cursor = conn.cursor()
    # get account information
    cursor.execute("SELECT * FROM customers WHERE customer_id = ?", (user_id,))
    customer = cursor.fetchone()
    # get booking details
    cursor.execute("""
           SELECT booking_id, date, time, city, address, postcode
           FROM bookings
           WHERE customer_id = ?
           ORDER BY date DESC
       """, (user_id,))
    booking_info = cursor.fetchone()

    conn.close()

    if not customer:
        return "User not found", 404

    confirm_cancel = request.args.get('confirm_cancel') == 'True'

    return render_template('profile.html', customer=customer, booking=booking_info, confirm_cancel=confirm_cancel)


@app.route('/quiz', methods=['GET'])
def show_quiz():
    return render_template('quiz.html', questions=list(enumerate(questions)))

@app.route('/quiz', methods=['POST'])
def calculate_score():

    # gets score by accumulating points
    total_score = 0
    for idx, (question, score) in enumerate(questions):
        answer = request.form.get(f'q{idx}')
        if answer == 'yes':
            total_score += score


    # connect to database
    user_id = session.get('user_id')
    conn = get_database_connection()
    cursor = conn.cursor()
    # add or replace score to database
    cursor.execute(
        "UPDATE customers SET score = ? WHERE customer_id = ?",
        (total_score, user_id)
    )
    conn.commit()
    conn.close()

    return render_template('result.html', score=total_score)

if __name__ == '__main__':
    app.run(debug=True)