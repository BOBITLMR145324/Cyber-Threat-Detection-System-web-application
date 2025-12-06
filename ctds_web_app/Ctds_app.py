from flask import Flask, render_template, request, redirect, url_for, session, flash
import pyodbc
import hashlib
import os
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
# IMPORTANT: Never share your actual secret key or connection details!
app.secret_key = os.getenv('SECRET_KEY')

def get_db_connection():
    """Establishes a connection to the SQL Server database."""
    conn_str = (
        f"DRIVER={{SQL Server}};"
        f"SERVER={os.getenv('DB_SERVER')};"
        f"DATABASE={os.getenv('DB_DATABASE')};"
        f"Trusted_Connection={os.getenv('DB_TRUSTED_CONNECTION')};"
    )
    return pyodbc.connect(conn_str)

def hash_password(password):
    """Hashes the password using SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()

@app.template_filter('datetimeformat')
def format_datetime(value, format_str='%Y-%m-%d %H:%M:%S'):
    """Format a datetime object for display."""
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.strftime(format_str)
    try:
        # Attempt to parse and format if it's a string
        # Use str() to handle potential pyodbc.Row issues with datetime types
        dt = datetime.strptime(str(value).split('.')[0], '%Y-%m-%d %H:%M:%S')
        return dt.strftime(format_str)
    except:
        return str(value)

@app.route('/', methods=['GET', 'POST'])
def index():
    """Handles the landing page, including Login, Register, and Reset."""
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Input validation for all actions
        if not username or not password:
            flash('Please ensure all required fields are entered.', 'danger')
            return redirect(url_for('index'))
            
        hashed = hash_password(password)
        conn = None
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # --- LOGIN LOGIC ---
            if action == 'login':
                # Note: This query uses the stored PasswordHash for comparison (secure only if used with SQL prepared statements, which pyodbc does for parameterized queries)
                cursor.execute("SELECT RoleID FROM Users WHERE Username=? AND PasswordHash=?", (username, hashed))
                role_row = cursor.fetchone()
                
                if role_row:
                    session['username'] = username
                    session['role'] = role_row[0]
                    flash(f"Welcome back, {username}!", 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid username or password.', 'danger')
            
            # --- REGISTER LOGIC (RoleID 3 is Viewer) ---
            elif action == 'register':
                # Check if username already exists
                cursor.execute("SELECT UserID FROM Users WHERE Username=?", (username,))
                if cursor.fetchone():
                    flash(f'Registration failed: Username "{username}" already exists.', 'danger')
                else:
                    cursor.execute("INSERT INTO Users (Username, PasswordHash, RoleID) VALUES (?, ?, ?)",
                                   (username, hashed, 3)) # Default to Viewer (RoleID 3)
                    conn.commit()
                    flash('Registration successful! You can now log in.', 'success')
            
            # --- PASSWORD RESET LOGIC ---
            elif action == 'reset':
                new_password = request.form.get('new_password')
                if not new_password:
                    flash('Please provide the new password for reset.', 'danger')
                    return redirect(url_for('index'))
                    
                new_hashed = hash_password(new_password)
                cursor.execute("UPDATE Users SET PasswordHash=? WHERE Username=?", (new_hashed, username))
                conn.commit()
                if cursor.rowcount == 0:
                     flash(f'Password reset failed: User "{username}" not found.', 'danger')
                else:
                    flash('Password reset successfully! Please log in with your new password.', 'success')
            
        except pyodbc.Error as e:
            flash(f"Database error: {str(e)}", 'danger')
        finally:
            if conn:
                conn.close()
            
    # If it's a GET request, always render the login page.
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    """Secured route for the main application dashboard."""
    if 'username' not in session:
        flash('Please log in to access the dashboard.', 'warning')
        return redirect(url_for('index'))
    
    role = session['role']
    
    data = []
    severity_data = [] # Data for Pie Chart 1
    type_data = []     # Data for Bar Chart 2
    
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # 1. Fetch main threat data based on role (using specific, secure queries)
        
        if role == 1:
            # Admin: 8 columns, secure (omitting PasswordHash, LogID, UserID, RoleID which were in the original AdminView)
            query = """
                SELECT 
                    t.ThreatID, t.ThreatType, t.Severity, t.Description, t.DetectedDate, 
                    l.Action, l.Timestamp, u.Username
                FROM Threats t 
                JOIN Logs l ON t.ThreatID = l.ThreatID 
                JOIN Users u ON l.UserID = u.UserID
                ORDER BY t.DetectedDate DESC
            """
        elif role == 2:
            # Analyst: 6 columns (Including Description, which was missing from the original AnalystView SQL)
            query = """
                SELECT 
                    t.ThreatID, t.ThreatType, t.Severity, t.Description, 
                    l.Action, l.Timestamp
                FROM Threats t 
                JOIN Logs l ON t.ThreatID = l.ThreatID
                ORDER BY t.DetectedDate DESC
            """
        else: # Role 3 (Viewer)
            # Viewer: 3 columns (matching the ViewerView definition)
            query = """
                SELECT 
                    t.ThreatType, t.Severity, t.DetectedDate
                FROM Threats t
                ORDER BY t.DetectedDate DESC
            """


        cursor.execute(query)
        # Convert pyodbc.Row objects to standard Python lists
        data = [list(row) for row in cursor.fetchall()]
        
        # 2. Fetch Severity aggregation data
        cursor.execute("SELECT Severity, COUNT(*) FROM Threats GROUP BY Severity")
        severity_data = [list(row) for row in cursor.fetchall()]
        
        # 3. Fetch ThreatType aggregation data
        cursor.execute("SELECT ThreatType, COUNT(*) FROM Threats GROUP BY ThreatType")
        type_data = [list(row) for row in cursor.fetchall()]

    except pyodbc.Error as e:
        flash(f"Database error loading dashboard: {str(e)}", 'danger')
    finally:
        if conn:
            conn.close()
    
    # Pass all required data to the template
    return render_template('dashboard.html',
                           data=data,
                           severity_data=severity_data,
                           type_data=type_data,
                           role=role,
                           username=session['username'])

@app.route('/logout')
def logout():
    """Logs out the user and redirects to the landing page."""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)