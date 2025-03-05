import sqlite3

def initialize_database():
    
    conn = sqlite3.connect('client_accounts.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS clients (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, 
                 username TEXT UNIQUE, 
                 password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS files (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, 
                 client_id INTEGER, 
                 file_name TEXT, 
                 file_size INTEGER, 
                 sent_time TEXT)''')
    conn.commit()
    conn.close()

def register_client(username, password):
    
    conn = sqlite3.connect('client_accounts.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO clients (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def login_client(username, password):

    conn = sqlite3.connect('client_accounts.db')
    c = conn.cursor()
    c.execute("SELECT id FROM clients WHERE username = ? AND password = ?", (username, password))
    client_id = c.fetchone()
    conn.close()
    return client_id[0] if client_id else None

def save_file_info(client_id, file_name, file_size, sent_time):
 
    conn = sqlite3.connect('client_accounts.db')
    c = conn.cursor()
    c.execute("INSERT INTO files (client_id, file_name, file_size, sent_time) VALUES (?, ?, ?, ?)",
              (client_id, file_name, file_size, sent_time))
    conn.commit()
    conn.close()

def get_client_files(client_id):
    conn = sqlite3.connect('client_accounts.db')
    c = conn.cursor()
    c.execute("SELECT DISTINCT file_name, file_size, sent_time FROM files WHERE client_id = ?", (client_id,))
    files = c.fetchall()
    conn.close()
    return files


def get_username_by_id(client_id):
  
    conn = sqlite3.connect('client_accounts.db')
    c = conn.cursor()
    c.execute("SELECT username FROM clients WHERE id = ?", (client_id,))
    username = c.fetchone()
    conn.close()
    return username[0] if username else None


initialize_database()
