from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3

app = Flask(__name__)
app.secret_key = "secret_movie_promo_key"
DB_NAME = "database.db"

# Secret code needed to register as a studio ADMIN (only agency staff know it)
ACCESS_CODE = "STUDIOHQ2026"


# ---------------------------------------------------------------
# DATABASE CONNECTION
# ---------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def column_exists(cursor, table, column):
    cursor.execute(f"PRAGMA table_info({table})")
    return any(row[1].lower() == column.lower() for row in cursor.fetchall())


# ---------------------------------------------------------------
# LOGIN PROTECTION  (role = None -> any logged-in user,
#                    role = 'admin' / 'client' -> only that role)
# ---------------------------------------------------------------
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if 'user_id' not in session:
                flash("Please sign in first to enter the studio.", "info")
                return redirect(url_for('login'))
            if role and session.get('role') != role:
                flash("Access denied: this area is not available for your account type.", "error")
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return wrapped
    return decorator


# ---------------------------------------------------------------
# CREATE TABLES (as per Data Dictionary) + SAFE UPGRADE OF OLD DB
# ---------------------------------------------------------------
def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''CREATE TABLE IF NOT EXISTS companies (
        company_id INTEGER PRIMARY KEY AUTOINCREMENT,
        company_name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        contact VARCHAR(15)
    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS admins (
        admin_id INTEGER PRIMARY KEY AUTOINCREMENT,
        company_id INTEGER NOT NULL,
        name VARCHAR(50) NOT NULL,
        username VARCHAR(50) UNIQUE NOT NULL,
        password VARCHAR(250) NOT NULL DEFAULT '',
        FOREIGN KEY (company_id) REFERENCES companies(company_id)
    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS clients (
        client_id INTEGER PRIMARY KEY AUTOINCREMENT,
        name VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        phone VARCHAR(15),
        password VARCHAR(250) NOT NULL DEFAULT ''
    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS movies (
        movie_id INTEGER PRIMARY KEY AUTOINCREMENT,
        client_id INTEGER NOT NULL,
        title VARCHAR(100) NOT NULL,
        genre VARCHAR(100) NOT NULL,
        releaseDate DATE NOT NULL,
        status VARCHAR(100) DEFAULT 'Pending',
        FOREIGN KEY (client_id) REFERENCES clients(client_id)
    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS promotions (
        promotion_id INTEGER PRIMARY KEY AUTOINCREMENT,
        movie_id INTEGER NOT NULL,
        admin_id INTEGER NOT NULL,
        platform VARCHAR(100) NOT NULL,
        budget DECIMAL(12,2) NOT NULL,
        status VARCHAR(20) DEFAULT 'Active',
        FOREIGN KEY (movie_id) REFERENCES movies(movie_id),
        FOREIGN KEY (admin_id) REFERENCES admins(admin_id)
    )''')

    # ---- Upgrade an OLD database (keeps all existing rows) ----
    if column_exists(cursor, 'companies', 'name') and not column_exists(cursor, 'companies', 'company_name'):
        cursor.execute("ALTER TABLE companies RENAME COLUMN name TO company_name")
    if not column_exists(cursor, 'companies', 'contact'):
        cursor.execute("ALTER TABLE companies ADD COLUMN contact VARCHAR(15)")
    if not column_exists(cursor, 'admins', 'password'):
        cursor.execute("ALTER TABLE admins ADD COLUMN password VARCHAR(250) NOT NULL DEFAULT ''")
    if not column_exists(cursor, 'clients', 'password'):
        cursor.execute("ALTER TABLE clients ADD COLUMN password VARCHAR(250) NOT NULL DEFAULT ''")
    if column_exists(cursor, 'movies', 'release_date') and not column_exists(cursor, 'movies', 'releaseDate'):
        cursor.execute("ALTER TABLE movies RENAME COLUMN release_date TO releaseDate")

    # ---- Default company + default admin ----
    cursor.execute("SELECT COUNT(*) FROM companies")
    if cursor.fetchone()[0] == 0:
        cursor.execute("INSERT INTO companies (company_name, email, contact) VALUES ('Prime Media Promotions', 'contact@primemedia.com', '9876543210')")
        cursor.execute("INSERT INTO admins (company_id, name, username, password) VALUES (1, 'Main Admin', 'admin', ?)",
                       (generate_password_hash('admin123'),))
    else:
        # old default admin had no password -> give it one so it can log in
        cursor.execute("UPDATE admins SET password = ? WHERE username = 'admin' AND (password IS NULL OR password = '')",
                       (generate_password_hash('admin123'),))

    conn.commit()
    conn.close()


# Runs when the app starts (locally AND on Render/gunicorn)
init_db()


# ---------------------------------------------------------------
# AUTH ROUTES : register (client), admin register, login, logout
# ---------------------------------------------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip().lower()
        phone = request.form.get('phone', '').strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for('register'))

        conn = get_db()
        existing = conn.execute("SELECT client_id, password FROM clients WHERE lower(email) = ?", (email,)).fetchone()
        hashed = generate_password_hash(password)

        if existing and existing['password']:
            conn.close()
            flash("This email is already registered. Please sign in.", "error")
            return redirect(url_for('login'))

        if existing:
            # client created before login existed -> attach the password to the same record
            conn.execute("UPDATE clients SET name = ?, phone = ?, password = ? WHERE client_id = ?",
                         (name, phone, hashed, existing['client_id']))
        else:
            conn.execute("INSERT INTO clients (name, email, phone, password) VALUES (?, ?, ?, ?)",
                         (name, email, phone, hashed))
        conn.commit()
        conn.close()

        flash("Your pass is ready! Sign in to enter the studio.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        name = request.form['name'].strip()
        username = request.form['username'].strip()
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        access_code = request.form['access_code'].strip()

        if access_code != ACCESS_CODE:
            flash("Invalid access code. Only agency staff can register as admin.", "error")
            return redirect(url_for('admin_register'))

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for('admin_register'))

        conn = get_db()
        if conn.execute("SELECT admin_id FROM admins WHERE username = ?", (username,)).fetchone():
            conn.close()
            flash("That username is already taken. Choose another.", "error")
            return redirect(url_for('admin_register'))

        conn.execute("INSERT INTO admins (company_id, name, username, password) VALUES (1, ?, ?, ?)",
                     (name, username, generate_password_hash(password)))
        conn.commit()
        conn.close()

        flash("Admin account created! Sign in from the Admin tab.", "success")
        return redirect(url_for('login', role='admin'))

    return render_template('admin_register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))

    selected_role = request.args.get('role', 'client')

    if request.method == 'POST':
        selected_role = request.form.get('role', 'client')
        identifier = request.form['identifier'].strip()
        password = request.form['password']

        conn = get_db()
        if selected_role == 'admin':
            user = conn.execute("SELECT admin_id AS id, name, password FROM admins WHERE username = ?",
                                (identifier,)).fetchone()
        else:
            user = conn.execute("SELECT client_id AS id, name, password FROM clients WHERE lower(email) = ?",
                                (identifier.lower(),)).fetchone()
        conn.close()

        if user and user['password'] and check_password_hash(user['password'], password):
            session.clear()
            session['user_id'] = user['id']
            session['role'] = selected_role
            session['user_name'] = user['name']
            flash(f"Welcome to the studio, {user['name']}!", "success")
            if selected_role == 'admin':
                return redirect(url_for('admin_panel'))
            return redirect(url_for('index'))

        flash("Invalid credentials. Please check your details and try again.", "error")

    return render_template('login.html', selected_role=selected_role)


@app.route('/logout')
def logout():
    session.clear()
    flash("You have been signed out. See you at the next premiere!", "info")
    return redirect(url_for('login'))


# ---------------------------------------------------------------
# DASHBOARD  (any logged-in user)
# ---------------------------------------------------------------
@app.route('/')
@login_required()
def index():
    conn = get_db()

    promotions = conn.execute('''
        SELECT p.promotion_id, m.title, m.genre, p.platform, p.budget, p.status
        FROM promotions p
        JOIN movies m ON p.movie_id = m.movie_id
    ''').fetchall()

    total_campaigns = len(promotions)
    total_budget = conn.execute("SELECT COALESCE(SUM(budget), 0) FROM promotions").fetchone()[0]
    total_movies = conn.execute("SELECT COUNT(*) FROM movies").fetchone()[0]
    conn.close()

    return render_template(
        'index.html',
        promotions=promotions,
        total_campaigns=total_campaigns,
        total_budget=total_budget,
        total_movies=total_movies
    )


# ---------------------------------------------------------------
# CLIENT AREA : submit movie + see my submissions
# ---------------------------------------------------------------
@app.route('/submit-movie', methods=['GET', 'POST'])
@login_required('client')
def submit_movie():
    if request.method == 'POST':
        title = request.form['title'].strip()
        genre = request.form['genre']
        release_date = request.form['release_date']

        conn = get_db()
        conn.execute("INSERT INTO movies (client_id, title, genre, releaseDate) VALUES (?, ?, ?, ?)",
                     (session['user_id'], title, genre, release_date))
        conn.commit()
        conn.close()

        flash("Movie submitted successfully! Pending admin approval.", "success")
        return redirect(url_for('submit_movie'))

    conn = get_db()
    my_movies = conn.execute('''
        SELECT title, genre, releaseDate AS release_date, status
        FROM movies WHERE client_id = ? ORDER BY movie_id DESC
    ''', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('submit_movie.html', my_movies=my_movies)


# ---------------------------------------------------------------
# ADMIN AREA : review, approve/reject, publish, company profile
# ---------------------------------------------------------------
@app.route('/admin')
@login_required('admin')
def admin_panel():
    conn = get_db()
    movies = conn.execute('''
        SELECT m.movie_id, m.title, m.genre, m.releaseDate AS release_date, m.status, c.name AS client_name
        FROM movies m
        JOIN clients c ON m.client_id = c.client_id
        ORDER BY m.movie_id DESC
    ''').fetchall()
    conn.close()
    return render_template('admin.html', movies=movies)


@app.route('/admin/action/<int:movie_id>/<string:action>')
@login_required('admin')
def movie_action(movie_id, action):
    if action not in ('approve', 'reject'):
        flash("Invalid action.", "error")
        return redirect(url_for('admin_panel'))

    status = 'Approved' if action == 'approve' else 'Rejected'
    conn = get_db()
    conn.execute("UPDATE movies SET status = ? WHERE movie_id = ?", (status, movie_id))
    conn.commit()
    conn.close()
    flash(f"Movie status updated to {status}.", "info")
    return redirect(url_for('admin_panel'))


@app.route('/admin/publish-promotion', methods=['POST'])
@login_required('admin')
def publish_promotion():
    movie_id = request.form['movie_id']
    platform = request.form['platform']

    try:
        budget = float(request.form['budget'])
    except ValueError:
        flash("Please enter a valid budget amount.", "error")
        return redirect(url_for('admin_panel'))

    conn = get_db()
    movie = conn.execute("SELECT status FROM movies WHERE movie_id = ?", (movie_id,)).fetchone()
    if not movie or movie['status'] != 'Approved':
        conn.close()
        flash("Only approved movies can be promoted.", "error")
        return redirect(url_for('admin_panel'))

    conn.execute(
        "INSERT INTO promotions (movie_id, admin_id, platform, budget, status) VALUES (?, ?, ?, ?, 'Active')",
        (movie_id, session['user_id'], platform, budget)
    )
    conn.commit()
    conn.close()

    flash("Promotion campaign started successfully!", "success")
    return redirect(url_for('index'))


@app.route('/company', methods=['GET', 'POST'])
@login_required('admin')
def company_profile():
    conn = get_db()
    if request.method == 'POST':
        conn.execute("UPDATE companies SET company_name = ?, email = ?, contact = ? WHERE company_id = 1",
                     (request.form['company_name'].strip(),
                      request.form['email'].strip(),
                      request.form.get('contact', '').strip()))
        conn.commit()
        flash("Company Profile Updated Successfully!", "info")

    company = conn.execute(
        "SELECT company_id, company_name AS name, email, contact FROM companies WHERE company_id = 1"
    ).fetchone()
    conn.close()
    return render_template('company.html', company=company)


if __name__ == '__main__':
    app.run(debug=True)