from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash  
from datetime import datetime, timedelta 


# App Initialization

app = Flask(__name__)
app.secret_key="myverysecretkey"


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'suhithadevasani@gmail.com'
app.config['MAIL_PASSWORD'] = 'xkxt gbnb tuej gaig'
app.config['MAIL_DEFAULT_SENDER'] = 'suhithadevasani@gmail.com'

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# Database Connection

def get_db_connection():
    conn = sqlite3.connect('notes.db')
    conn.row_factory = sqlite3.Row
    return conn


# --------------------
# Home (redirect)
# --------------------
@app.route('/')
def home():
    # If logged in -> show notes, else -> show login
    if 'user_id' in session:
        return redirect('/viewall')
    return redirect('/login')

# --------------------
# Register Route
# --------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    # If POST -> process registration form
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']

        # Basic checks (non-empty)
        if not username or not email or not password:
            flash("Please fill all fields.", "danger")
            return redirect('/register')

        # Hash the password before saving
        hashed_pw = generate_password_hash(password)

        conn = get_db_connection()
        cur = conn.cursor()

        # Check if username already exists
        cur.execute("SELECT id FROM users WHERE username = ?", (username,))
        exists = cur.fetchone()
        if exists:
            # Close connection and inform user
            cur.close()
            conn.close()
            flash("Username already taken. Choose another.", "danger")
            return redirect('/register')

        # Insert new user into users table
        cur.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                    (username, email, hashed_pw))
        conn.commit()
        cur.close()
        conn.close()

        flash("Registration successful! You can now log in.", "success")
        return redirect('/login')

    # If GET -> show registration form
    return render_template('register.html')

# --------------------
# Login Route
# --------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    # If POST -> authenticate
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        # Basic check
        if not username or not password:
            flash("Please enter username and password.", "danger")
            return redirect('/login')

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        # Check whether user exists and password matches
        if user and check_password_hash(user['password'], password):
            # Save user id and username in session for future access control
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash(f"Welcome, {user['username']}!", "success")
            return redirect('/viewall')
        else:
            flash("Invalid username or password.", "danger")
            return redirect('/login')

    # If GET -> show login page
    return render_template('login.html')


#About Route
@app.route('/About')
def About():
    return render_template('About.html')


#Contact Route
@app.route('/contact')
def contact():
    return render_template('contact.html')

# --------------------
# Logout Route
# --------------------
@app.route('/logout')
def logout():
    # Clear session data
    session.clear()
    flash("You have been logged out.", "info")
    return redirect('/login')

# --------------------
# Add Note (CREATE)
# --------------------
@app.route('/addnote', methods=['GET', 'POST'])
def addnote():
    # Ensure user is logged in
    if 'user_id' not in session:
        flash("Please login first.", "warning")
        return redirect('/login')

    if request.method == 'POST':
        title = request.form['title'].strip()
        content = request.form['content'].strip()
        user_id = session['user_id']

        if not title or not content:
            flash("Title and content cannot be empty.", "danger")
            return redirect('/addnote')

        conn = get_db_connection()
        cur = conn.cursor()
        # Save note with user_id to keep notes private
        cur.execute("INSERT INTO notes (title, content, user_id) VALUES (?, ?, ?)",
                    (title, content, user_id))
        conn.commit()
        cur.close()
        conn.close()

        flash("Note added successfully.", "success")
        return redirect('/viewall')

    # GET -> show add note form
    return render_template('addnote.html')

# --------------------
# View All Notes (READ ALL for logged-in user)
# --------------------
@app.route('/viewall')
def viewall():
    # Ensure user logged in
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    conn = get_db_connection()
    cur = conn.cursor()

    # Fetch only notes that belong to this user
    cur.execute("SELECT id, title, content, created_at FROM notes WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
    notes = cur.fetchall()
    cur.close()
    conn.close()

    return render_template('viewnotes.html', notes=notes)

# --------------------
# View Single Note (READ ONE) - restricted
# --------------------
@app.route('/viewnotes/<int:note_id>')
def viewnotes(note_id):
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    conn = get_db_connection()
    cur = conn.cursor()

    # Select note only if it belongs to current user
    cur.execute("SELECT id, title, content, created_at FROM notes WHERE id = ? AND user_id = ?", (note_id, user_id))
    note = cur.fetchone()
    cur.close()
    conn.close()

    if not note:
        # Either note doesn't exist or doesn't belong to the user
        flash("You don't have access to this note.", "danger")
        return redirect('/viewall')

    return render_template('singlenote.html', note=note)

# --------------------
# Update Note (UPDATE) - restricted
# --------------------
@app.route('/updatenote/<int:note_id>', methods=['GET', 'POST'])
def updatenote(note_id):
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    conn = get_db_connection()
    cur = conn.cursor()


    # Check existence and ownership
    cur.execute("SELECT id, title, content FROM notes WHERE id = ? AND user_id = ?", (note_id, user_id))
    note = cur.fetchone()

    if not note:
        cur.close()
        conn.close()
        flash("You are not authorized to edit this note.", "danger")
        return redirect('/viewall')

    if request.method == 'POST':
        # Get updated data
        title = request.form['title'].strip()
        content = request.form['content'].strip()
        if not title or not content:
            flash("Title and content cannot be empty.", "danger")
            return redirect(url_for('updatenote', note_id=note_id))

        # Update query guarded by user_id
        cur.execute("UPDATE notes SET title = ?, content = ? WHERE id = ? AND user_id = ?",
                    (title, content, note_id, user_id))
        conn.commit()
        cur.close()
        conn.close()
        flash("Note updated successfully.", "success")
        return redirect('/viewall')

    # If GET -> render update form with existing note data
    cur.close()
    conn.close()
    return render_template('updatenote.html', note=note)

# --------------------
# Delete Note (DELETE) - restricted
# --------------------
@app.route('/deletenote/<int:note_id>', methods=['POST'])
def deletenote(note_id):
    # This route expects a POST request (safer than GET for delete)
    if 'user_id' not in session:
        return redirect('/login')

    user_id = session['user_id']
    conn = get_db_connection()
    cur = conn.cursor()
    # Delete only if the note belongs to the current user
    cur.execute("DELETE FROM notes WHERE id = ? AND user_id = ?", (note_id, user_id))
    conn.commit()
    cur.close()
    conn.close()
    flash("Note deleted.", "info")
    return redirect('/viewall')


# ----------FORGOT PASSWORD-------------


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email'].strip()

        if not email:
            flash("Email is required.", "danger")
            return redirect('/forgot-password')

        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute("SELECT id FROM users WHERE email = ?", (email,))
        user = cur.fetchone()

        if not user:
            flash("No account found with this email.", "danger")
            cur.close()
            conn.close()
            return redirect('/forgot-password')

        # Generate secure token
        token = serializer.dumps(email, salt='reset-password')
        expiry = datetime.now() + timedelta(minutes=15)

        cur.execute(
            "UPDATE users SET reset_token=?, reset_token_expiry=? WHERE email=?",
            (token, expiry, email)
        )
        conn.commit()
        cur.close()
        conn.close()

        reset_link = url_for('reset_password', token=token, _external=True)

        # Send Email
        msg = Message(
            subject="Password Reset Request",
            recipients=[email]
        )
        msg.body = f"""
Hello,

Click the link below to reset your password:
{reset_link}

This link will expire in 15 minutes.

If you did not request this, please ignore this email.
"""
        mail.send(msg)

        flash("Password reset link sent to your email.", "info")
        return redirect('/login')

    return render_template('forgot_password.html')


# ---------reset password route------------

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE reset_token = ?", (token,))
    user = cur.fetchone()

    if not user:
        flash("Invalid or expired reset link.", "danger")
        cur.close()
        conn.close()
        return redirect('/login')

    expiry = datetime.fromisoformat(user['reset_token_expiry'])
    if expiry < datetime.now():
        flash("Reset link has expired.", "danger")
        cur.close()
        conn.close()
        return redirect('/login')

    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm_password']

        if not password or not confirm:
            flash("All fields are required.", "danger")
            return redirect(request.url)

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(request.url)

        hashed_pw = generate_password_hash(password)

        cur.execute("""
            UPDATE users
            SET password = ?, reset_token = NULL, reset_token_expiry = NULL
            WHERE id = ?
        """, (hashed_pw, user['id']))

        conn.commit()
        cur.close()
        conn.close()

        flash("Password reset successful. Please login.", "success")
        return redirect('/login')

    cur.close()
    conn.close()
    return render_template('reset_password.html')
#-----------search notes route------------


# --------------------
@app.route('/search', methods=['POST'])
def search_notes():
    if 'user_id' not in session:
        return redirect('/login')

    query = request.form.get('q', '').strip()
    user_id = session['user_id']

    conn = get_db_connection()
    cur = conn.cursor()


    # 🔍 SEARCH ONLY IN TITLE
    cur.execute("""
        SELECT id, title, content, created_at
        FROM notes
        WHERE user_id = ?
        AND title LIKE ?
        ORDER BY created_at DESC
    """, (user_id, f"%{query}%"))

    notes = cur.fetchall()
    cur.close()
    conn.close()

    return render_template(
        'search_results.html',
        notes=notes,
        query=query
    )


# --------------------
# Run App
# --------------------
if __name__ == '__main__':
    # debug=True for development only
    app.run(debug=True)