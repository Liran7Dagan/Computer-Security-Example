from flask import Flask, request, render_template
import sqlite3, json, os, hashlib, hmac, re, html

app = Flask(__name__)

def load_config():
    with open('password_config.json', 'r') as file:
        return json.load(file)

def init_db():
    conn = sqlite3.connect('comunication_ltd.db')
    with open('schema.sql', 'r') as file:
        conn.executescript(file.read())
    conn.commit()
    conn.close()
    print("Database initialized successfully.")

def get_db_connection():
    conn = sqlite3.connect('comunication_ltd.db')
    conn.row_factory = sqlite3.Row
    return conn

def validate_password(password, config):
    if len(password) < config['min_length']:
        return False, f"הסיסמה חייבת להכיל לפחות {config['min_length']} תווים."
    if config['require_complex']:
        if not re.search(r'[A-Z]', password): return False, "הסיסמה חייבת להכיל אות גדולה."
        if not re.search(r'[a-z]', password): return False, "הסיסמה חייבת להכיל אות קטנה."
        if not re.search(r'\d', password): return False, "הסיסמה חייבת להכיל ספרה."
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password): return False, "הסיסמה חייבת להכיל תו מיוחד."
    return True, ""

@app.route('/')
def home():
    return "ברוכים הבאים למערכת Comunication_LTD!"

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        config = load_config()
        is_valid, error_msg = validate_password(password, config)
        if not is_valid:
            return error_msg
        
        salt = os.urandom(16).hex()
        password_hash = hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()
        
        try:
            conn = get_db_connection()
            conn.execute(
                'INSERT INTO Users (username, email, password_hash, salt) VALUES (?, ?, ?, ?)',
                (username, email, password_hash, salt)
            )
            conn.commit()
            conn.close()
            return f"המשתמש {username} נרשם בהצלחה!"
        except sqlite3.IntegrityError:
            return "שם המשתמש או האימייל כבר קיימים במערכת."
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM Users WHERE username = ?', (username,)).fetchone()
        
        if user is None:
            conn.close()
            return "המשתמש אינו קיים במערכת."
            
        config = load_config()
        if user['login_attempts'] >= config['max_login_attempts']:
            conn.close()
            return "החשבון ננעל עקב חריגה ממספר ניסיונות ההתחברות המותרים."
            
        input_hash = hmac.new(user['salt'].encode(), password.encode(), hashlib.sha256).hexdigest()
        
        if input_hash == user['password_hash']:
            conn.execute('UPDATE Users SET login_attempts = 0 WHERE id = ?', (user['id'],))
            conn.commit()
            conn.close()
            return f"ברוך הבא למערכת מידע Comunication_LTD, {username}!"
        else:
            attempts = user['login_attempts'] + 1
            conn.execute('UPDATE Users SET login_attempts = ? WHERE id = ?', (attempts, user['id']))
            conn.commit()
            conn.close()
            return f"סיסמה שגויה. ניסיון {attempts} מתוך {config['max_login_attempts']}."
            
    return render_template('login.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    message = ""
    if request.method == 'POST':
        full_name = request.form['full_name']
        details = request.form['details']
        
        # קידוד תווים מיוחדים למניעת Stored XSS
        safe_full_name = html.escape(full_name)
        safe_details = html.escape(details)
        
        conn = get_db_connection()
        # שימוש בשאילתה פרמטרית למניעת SQL Injection
        conn.execute('INSERT INTO Customers (full_name, details) VALUES (?, ?)', (safe_full_name, safe_details))
        conn.commit()
        conn.close()
        
        # בניית הודעת ההצלחה שתוצג למסך עם שם הלקוח החדש
        message = f"הלקוח החדש '{safe_full_name}' הוזן בהצלחה למערכת!"
        
    return render_template('dashboard.html', message=message)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        
        # יצירת ערך אקראי וגיבוב באמצעות SHA-1
        random_value = os.urandom(6).hex()
        token_sha1 = hashlib.sha1(random_value.encode()).hexdigest()
        
        conn = get_db_connection()
        conn.execute('INSERT INTO ResetTokens (email, token_hash) VALUES (?, ?)', (email, token_sha1))
        conn.commit()
        conn.close()
        
        # הדפסה לטרמינל כדי לדמות שליחה למייל
        print(f"\n--- EMAIL SIMULATION ---", flush=True)
        print(f"To: {email}", flush=True)
        print(f"Your reset code is: {random_value}", flush=True)
        print(f"------------------------\n", flush=True)
        
        return "קוד השחזור נשלח למייל (בדוק את הטרמינל). <a href='/reset_password'>לחץ כאן למעבר להזנת הקוד</a>"
        
    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        token = request.form['token']
        new_password = request.form['new_password']
        
        # גיבוב הקלט והשוואה למה שנשמר במסד הנתונים
        token_sha1 = hashlib.sha1(token.encode()).hexdigest()
        
        conn = get_db_connection()
        record = conn.execute('SELECT * FROM ResetTokens WHERE token_hash = ?', (token_sha1,)).fetchone()
        
        if record:
            email = record['email']
            
            # בדיקת חוקיות הסיסמה החדשה
            config = load_config()
            is_valid, error_msg = validate_password(new_password, config)
            if not is_valid:
                conn.close()
                return error_msg
                
            # הצפנת הסיסמה החדשה (HMAC + Salt)
            salt = os.urandom(16).hex()
            password_hash = hmac.new(salt.encode(), new_password.encode(), hashlib.sha256).hexdigest()
            
            # עדכון משתמש ומחיקת הטוקן
            conn.execute('UPDATE Users SET password_hash = ?, salt = ? WHERE email = ?', (password_hash, salt, email))
            conn.execute('DELETE FROM ResetTokens WHERE id = ?', (record['id'],))
            conn.commit()
            conn.close()
            
            return "הסיסמה שונתה בהצלחה! <a href='/login'>התחבר למערכת</a>"
        else:
            conn.close()
            return "קוד שחזור שגוי."
            
    return render_template('reset_password.html')

if __name__ == '__main__':
    init_db()
    config = load_config()
    print(f"Password config loaded. Min length: {config['min_length']}")
    app.run(debug=True)