from flask import Flask, render_template, request, redirect, session, jsonify, url_for, send_from_directory
from flask_cors import CORS
import json
import sqlite3
import os
import sys
import traceback
import time  
from markupsafe import escape
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash 

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from flask_wtf.csrf import CSRFProtect


app = Flask(__name__)
app.secret_key = "12345"  

csrf= CSRFProtect(app) #Enable the CSRF Protect





# Initialize Limiter
limiter = Limiter(get_remote_address, app=app)

# Apply global rate limit
# Here, the limit is 5 requests per minute for all routes
@app.before_request
@limiter.limit("5 per minute")  # Global rate limit: 5 requests per minute per IP
def before_request():
    pass  # This function will be executed before each request



CORS(app, resources={r"/*": {"origins": "*"}})


DEFAULT_CREDENTIALS = {
    "admin": "admin123",  
    "test": "test123",    
    "demo": "demo123"     
}

# Initialise database
def init_db():
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    
    # Create users table with email field (if not exists)
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT UNIQUE
        )
    """)
    
    # Add profiles table with sensitive information
    c.execute("""
        CREATE TABLE IF NOT EXISTS profiles (
            user_id INTEGER PRIMARY KEY,
            full_name TEXT,
            email TEXT,
            phone TEXT,
            credit_card TEXT,
            address TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)
    
    # Add default users if they don't exist
    for username, password in DEFAULT_CREDENTIALS.items():
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        if not c.fetchone():
            # Add email for each default user
            email = f"{username}@example.com"
            c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
                     (username, password, email))
    
    conn.commit()
    conn.close()

# Load pizza data
def load_pizzas():
    try:
        with open("pizza.json", "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return []

# Save pizza data
def save_pizzas(pizzas):
    # Ensure backup directory exists
    os.makedirs("static/backup", exist_ok=True)
    
    # Save to both main file and backup
    with open("pizza.json", "w") as f:
        json.dump(pizzas, f, indent=4)
    
    with open("static/backup/pizza.json.bak", "w") as f:
        json.dump(pizzas, f, indent=4)



# Verbose error route
@app.route("/error_test")
def error_test():
    username = request.args.get("username")
    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    c.execute(query)  
    return f"Executed query: {query}"


@app.route("/")
def index():
    pizzas = load_pizzas()
    return render_template("index.html", pizzas=pizzas)

# Vulnerability 1 - SQL Injection - Fixed using parameterized statements 
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Check default credentials first (not stored in the database)
        if username in DEFAULT_CREDENTIALS and DEFAULT_CREDENTIALS[username] == password:
            session['user'] = username
            return redirect(url_for('index'))

        # Connect to the database securely
        conn = sqlite3.connect("users.db")
        c = conn.cursor()

        # SECURE: Using parameterised statements: Instead of inserting variables directly, use placeholders (?) which SQLite replaces with actual values safely
        c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = c.fetchone()  # Fetch user data safely

        conn.close()  # Close the database connection

        if user:
            session['user'] = user[1]  # Store username in session
            return redirect(url_for('index'))
        else:
            return "Invalid credentials! <a href='/'>Try again</a>"

    return render_template("index.html")

# Vulnerability 2 - Reflective Cross Site Scripting - Self Cross Site Scripting - Fixed using Escape Function
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username")
        
        # Escape the username input to prevent XSS
        escaped_username = escape(username)  # Ensures any HTML/JS is safely rendered as text
        
        timestamp = int(time.time())
        token = f"{escaped_username}_{timestamp}"  
        
        # Use the escaped username in the URL to avoid injecting untrusted content
        reset_link = f"http://127.0.0.1:5000/password-reset?username={escaped_username}&token={token}"
        
        return f"""
            <h2>Password Reset Requested</h2>
            <p>A password reset link has been generated.</p>
            <p>Normally this would be emailed, but for testing, here's the link:</p>
            <p><a href="{reset_link}">{reset_link}</a></p>  <!-- Displaying the escaped link -->
            <p><a href="/">Back to login</a></p>
        """
    
    return """
        <h2>Forgot Password</h2>
        <form method="POST">
            <p>Username: <input type="text" name="username" required></p>
            <p><input type="submit" value="Reset Password"></p>
        </form>
    """

# Vulnerability 3 - Command Execution - Fixed by just excluding os system calls 
@app.route("/debug/<path:file_path>")
def debug_file(file_path):
    try:
        # Read the file content securely without exposing system info
        with open(file_path, 'r') as f:
            content = f.read()

        # Return the file content without exposing system info
        return f"""
            <h2>File Content</h2>
            <pre>{content}</pre>
        """
    except Exception as e:
        # Return a generic error message, no system information exposed
        return f"""
            <h2>Error Reading File</h2>
            <p>Path: {file_path}</p>
            <p>Error: {str(e)}</p>
        """, 500

# Vulnerabiloty 4 - Clickjacking - Fixed by adding Content Security Policies 
@app.after_request
def set_csp(response):
    # Add the Content-Security-Policy header to the response
    response.headers['Content-Security-Policy'] = "frame-ancestors 'self';"
    return response


# Vulneraiilty 6 - Directory traversal - Fixed by adding parameters to the download path 
@app.route("/download")
def download():
    filename = request.args.get("file")
    
    # Use os.path.basename to sanitise the filename and prevent directory traversal
    safe_filename = os.path.basename(filename)
    
    # Construct the file path from the uploads folder (not static/uploads)
    file_path = os.path.join("uploads", safe_filename)
    
    # Check if the file exists
    if os.path.exists(file_path):
        return send_from_directory("uploads", safe_filename)
    else:
        return "File not found", 404

# Vulnerability 7 - Stored XSS - Fixed by using the same esacpe funtion of flask as the reflective xss
@app.route("/add_to_cart", methods=["POST"])
def add_to_cart():
    pizza_name = request.form.get("pizza_name")
    
    # Escape the pizza name to prevent XSS in the cart
    escaped_pizza_name = escape(pizza_name)
    
    pizzas = load_pizzas()
    pizza = next((p for p in pizzas if p["name"] == escaped_pizza_name), None)
    
    if pizza:
        cart_item = {
            "name": escaped_pizza_name,  # Use the escaped pizza name
            "description": pizza["description"],
            "image": pizza["image"],
            "price": pizza["price"],
            "quantity": 1
        }
        
        if 'cart' not in session:
            session['cart'] = []
        
        existing_item = next((item for item in session['cart'] if item["name"] == escaped_pizza_name), None)
        if existing_item:
            existing_item["quantity"] += 1
        else:
            session['cart'].append(cart_item)
        
        session.modified = True
        return redirect(url_for('cart'))
    
    return "Pizza not found!", 404

#Vulernability 8 - File Upload - Fixed by having restrciton and use MIME

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'} # Allowed extensions for images

# Function to check allowed file extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Function to check if the file is an image (using MIME type)
def is_image(file):
    return file.content_type.startswith('image/')  # Ensure it's an image MIME type

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        file = request.files["file"]

        # Check if the file is allowed by extension and MIME type
        if file and allowed_file(file.filename) and is_image(file):
            # Secure the filename to prevent directory traversal attacks
            filename = secure_filename(file.filename)

            # Ensure the upload directory exists
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])

            # Save the file to the specified folder
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return "File uploaded successfully!"

        # If not a valid image, return an error message
        return "Invalid file type. Only image files (png, jpg, jpeg, gif) are allowed."

    return '''
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file">
        <button type="submit">Upload</button>
    </form>
    '''

# Vulnerability 9 - Broken Access Control - Fixed by checking if admim 
# and checking if they are acessing their own profile
@app.route("/profile/<int:user_id>")
def view_profile(user_id):
    # Check if the user is logged in before accessing profiles
    if "user" not in session:
        return "Access denied! Please log in first.", 403

    conn = sqlite3.connect("users.db")
    c = conn.cursor()

    # Retrieve the logged-in user's ID and username from the database
    c.execute("SELECT id, username FROM users WHERE username = ?", (session["user"],))
    current_user = c.fetchone()

    if not current_user:
        conn.close()
        return "User not found.", 403  # Prevent access if the user does not exist

    current_user_id, current_username = current_user

    # Enforce access control: users can only view their own profile unless they are an admin
    if current_user_id != user_id and current_username != "admin":
        conn.close()
        return "Access denied! You are not authorised to view this profile.", 403

    # Retrieve profile information for the requested user ID
    c.execute("""
        SELECT u.username, p.* 
        FROM users u 
        LEFT JOIN profiles p ON u.id = p.user_id 
        WHERE u.id = ?
    """, (user_id,))

    data = c.fetchone()
    conn.close()

    if data:
        # Display the profile details securely
        return f"""
            <h2>User Profile</h2>
            <pre>
            Username: {data[0]}
            Full Name: {data[2]}
            Email: {data[3]}
            Phone: {data[4]}
            Credit Card: {data[5]}
            Address: {data[6]}
            </pre>
            <p><a href="/">Back to Home</a></p>
        """
    
    return "Profile not found.", 404  # Return 404 if no profile is found


#Vulnerability 13 - Password Managment - Fixed by password hashing 
@app.route("/register", methods=["GET", "POST"])
def register_page():
    if request.method == "GET":
        return render_template("register.html")
    
    username = request.form["username"]
    password = request.form["password"]

    hashed_password = generate_password_hash(password)  # Hash the password before storing

    conn = sqlite3.connect("users.db")
    c = conn.cursor()
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
    conn.commit()
    conn.close()

    return redirect(url_for("index"))

@app.route("/reset", methods=["GET", "POST"])
def reset_password():
    if request.method == "POST":
        username = request.form["username"]
        token = request.form["token"]
        if reset_tokens.get(username) == token:
            return "Password reset successful!"
    return render_template("reset.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# Allowed extensions for images
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Function to check allowed file extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Function to check if the file is an image (using MIME type)
def is_image(file):
    return file.content_type.startswith('image/')  # Ensure it's an image MIME type

@app.route("/admin", methods=["GET", "POST"])
def admin():
    if "user" not in session or session["user"] != "admin":
        return "Access Denied! <a href='/'>Go back</a>"

    pizzas = load_pizzas()

    if request.method == "POST":
        name = request.form["name"]
        description = request.form["description"]
        price = float(request.form.get("price", 0))
        image_file = request.files.get("image")
        image_filename = None

        if image_file:
            # Restrict upload to image files only
            if image_file.filename == "" or not allowed_file(image_file.filename) or not is_image(image_file):
                return "Invalid file type. Only image files (png, jpg, jpeg, gif) are allowed.", 400
            filename = secure_filename(image_file.filename)
            image_filename = f"static/images/{filename}"
            image_file.save(image_filename)

        if "update" in request.form:
            pizza_id = int(request.form["update"])
            pizzas[pizza_id]["name"] = name
            pizzas[pizza_id]["description"] = description
            pizzas[pizza_id]["price"] = price
            if image_filename:
                pizzas[pizza_id]["image"] = image_filename
        elif "delete" in request.form:
            pizza_id = int(request.form["delete"])
            if 0 <= pizza_id < len(pizzas):
                pizzas.pop(pizza_id)
                save_pizzas(pizzas)
                return redirect("/admin")
        else:
            pizzas.append({
                "name": name,
                "description": description,
                "price": price,
                "image": image_filename
            })

        save_pizzas(pizzas)
        return redirect("/admin")

    return render_template("admin.html", pizzas=pizzas)


@app.route("/cart")
def cart():
    cart_items = session.get('cart', [])
    return render_template("cart.html", cart_items=cart_items)

@app.route("/update_cart", methods=["POST"])
def update_cart():
    item_name = request.form.get("item")
    quantity = request.form.get("quantity")
    
    if 'cart' in session:
        for item in session['cart']:
            if item["name"] == item_name:
                item["quantity"] = int(quantity)
                session.modified = True
                break
    
    return "Updated", 200

@app.route("/remove_from_cart", methods=["POST"])
def remove_from_cart():
    item_name = request.form.get("item")
    
    if 'cart' in session:
        session['cart'] = [item for item in session['cart'] if item["name"] != item_name]
        session.modified = True
    
    return "Removed", 200

@app.route("/api/docs")
def api_docs():
    return render_template("api_docs.html")

# Vulnerability 11 - User Enumeration - Foxed by addign gernric message no matter what
@app.route("/user/<username>")
def get_user(username):
    try:
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        # Use parameterized queries to prevent SQL injection
        query = "SELECT username FROM users WHERE username = ?"
        c.execute(query, (username,))  # Use the username as a parameter
        user = c.fetchone()
        conn.close()
        
        # Return the same generic response regardless of whether the user exists or not
        return "Nice try Sir"  # Same response, doesn't reveal anything
        
    except Exception as e:
        return f"Database Error: {str(e)}", 500

# Vulnerabilty 12 - Information Leakage - Fixed by Hidding server heading
@app.after_request
def remove_server_header(response):
    response.headers["Server"] = "Hidden"
    return response


@app.errorhandler(500)
def internal_error(error):
    import traceback
    error_details = {
        'error_type': str(type(error).__name__),
        'error_message': str(error),
        'stack_trace': traceback.format_exc(),
        'python_version': sys.version,
        'flask_version': Flask.__version__,
        'debug_mode': app.debug,
        'database_path': 'users.db'
    }
    return f"""
        <h1>Internal Server Error</h1>
        <pre>
        Error Type: {error_details['error_type']}
        Message: {error_details['error_message']}
        
        Full Stack Trace:
        {error_details['stack_trace']}
        
        System Information:
        Python Version: {error_details['python_version']}
        Flask Version: {error_details['flask_version']}
        Debug Mode: {error_details['debug_mode']}
        Database: {error_details['database_path']}
        </pre>
    """, 500

@app.errorhandler(404)
def page_not_found(e):
    error_message = """
    Page not found. Please check our documentation for valid URLs.
    """
    return error_message, 404

@app.route("/create_profile", methods=["GET", "POST"])
def create_profile():
    if request.method == "POST":
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username = ?", (session.get('user'),))
        user = c.fetchone()
        
        if user:
            c.execute("""
                INSERT OR REPLACE INTO profiles 
                (user_id, full_name, email, phone, credit_card, address)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                user[0],
                request.form.get('full_name', 'John Doe'),
                request.form.get('email', 'john@example.com'),
                request.form.get('phone', '123-456-7890'),
                request.form.get('credit_card', '4111-1111-1111-1111'),
                request.form.get('address', '123 Main St, City, Country')
            ))
            conn.commit()
            conn.close()
            return redirect(f"/profile/{user[0]}")
            
    return """
        <h2>Create Profile</h2>
        <form method="POST">
            <p>Full Name: <input name="full_name" value="John Doe"></p>
            <p>Email: <input name="email" value="john@example.com"></p>
            <p>Phone: <input name="phone" value="123-456-7890"></p>
            <p>Credit Card: <input name="credit_card" value="4111-1111-1111-1111"></p>
            <p>Address: <input name="address" value="123 Main St, City, Country"></p>
            <p><input type="submit" value="Create Profile"></p>
        </form>
    """

@app.route("/password-reset", methods=["GET", "POST"])
def password_reset():
    username = request.args.get("username") or request.form.get("username")
    token = request.args.get("token") or request.form.get("token")
    
    if not username or not token:
        return "Missing username or token", 400
    
    if request.method == "POST":
        new_password = request.form.get("new_password")
        if not new_password:
            return "Missing new password", 400
        
        conn = sqlite3.connect("users.db")
        c = conn.cursor()
        query = f"UPDATE users SET password = '{new_password}' WHERE username = '{username}'"
        c.execute(query)
        conn.commit()
        conn.close()
        
        return """
            <h2>Password Updated</h2>
            <p>Your password has been updated successfully.</p>
            <p><a href="/">Login with new password</a></p>
        """
    
    return f"""
        <h2>Reset Password</h2>
        <form method="POST">
            <input type="hidden" name="username" value="{username}">
            <input type="hidden" name="token" value="{token}">
            <p>New Password: <input type="password" name="new_password" required></p>
            <p><input type="submit" value="Update Password"></p>
        </form>
    """

@app.route('/uploads/<path:filename>')
def serve_file(filename):
    return send_from_directory('uploads', filename)

if __name__ == "__main__":
    if not os.path.exists("uploads"):
        os.mkdir("uploads")
    
    if not os.path.exists("pizza.json"):
        save_pizzas([])  

    # Vulnerability 10 - Unencryted Communication - Man in the Middle Attacks 
    # Fixed by running server with open ssl to run on https not on http
    
    init_db()
    app.run(debug=True)




