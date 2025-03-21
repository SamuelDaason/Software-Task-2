import sqlite3

# Connect to the database
conn = sqlite3.connect('users.db')
cursor = conn.cursor()

# Query all usernames and passwords
print("Usernames and Passwords in Database:")
print("-" * 40)
cursor.execute("SELECT username, password FROM users")
rows = cursor.fetchall()
for username, password in rows:
    print(f"Username: {username:<15} Password: {password}")

conn.close()
