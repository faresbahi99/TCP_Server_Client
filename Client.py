import socket
import tkinter as tk
import os
import threading
import customtkinter as ctk

from tkinter import filedialog, messagebox, Menu, PhotoImage
from datetime import datetime
from database import register_client, login_client, save_file_info, get_client_files
from PIL import Image, ImageTk

client_id = None 
client_socket = None

def exit_app():
    root.destroy()
    root.quit()

def show_registration_login():
    reg_login_window = ctk.CTkToplevel()
    reg_login_window.title("Login / Register")
    reg_login_window.geometry("300x420")
    
    reg_login_window.iconbitmap('icons/client_icon.ico')  
      
    reg_login_window.resizable(False, False)
    reg_login_window.grab_set()
    reg_login_window.protocol("WM_DELETE_WINDOW", lambda: exit_app())

       
    title_frame = ctk.CTkFrame(reg_login_window, height=40, fg_color="#2E86C1")
    title_frame.pack(fill="x")


    title_label = ctk.CTkLabel(title_frame, text="WELLCOME", font=("Courier New", 22, "bold"))
    title_label.pack(pady=20)
    
   
    ctk.CTkLabel(reg_login_window, text="Username:", font=("courier new", 14)).place(x=30, y=100)
    username_entry = ctk.CTkEntry(reg_login_window, font=("Courier New", 14), width=200)
    username_entry.place(x=30, y=130)


    ctk.CTkLabel(reg_login_window, text="Password:", font=("Courier New", 14)).place(x=30, y=170)
    password_entry = ctk.CTkEntry(reg_login_window, show="*", font=("Courier New", 14), width=200)
    password_entry.place(x=30, y=200)

  
    confirm_password_label = ctk.CTkLabel(reg_login_window, text="Confirm Password:", font=("Courier New", 14))
    confirm_password_entry = ctk.CTkEntry(reg_login_window, show="*", font=("Courier New", 14), width=200)
    confirm_password_label.place(x=30, y=240)
    confirm_password_entry.place(x=30, y=270)
    confirm_password_label.place_forget()  
    confirm_password_entry.place_forget() 

    
    register_mode = ctk.BooleanVar(value=False)

    def toggle_mode():
        """Toggle between login and registration mode"""
        if register_mode.get():
           
            confirm_password_label.place(x=30, y=240)
            confirm_password_entry.place(x=30, y=270)
         
            proceed_button.configure(text="Register")
        else:
         
            confirm_password_label.place_forget()
            confirm_password_entry.place_forget()
           
            proceed_button.configure(text="Login")

    ctk.CTkCheckBox(reg_login_window, text="Register as a new user", variable=register_mode, command=toggle_mode,
                    font=("Courier New", 14)).place(x=30, y=320)

    def proceed():
      
        username = username_entry.get().strip()
        password = password_entry.get().strip()

        global client_id
        if register_mode.get():  
            confirm_password = confirm_password_entry.get().strip()
            if password != confirm_password:
                messagebox.showerror("Error", "Passwords do not match")
                return
            if register_client(username, password):
                messagebox.showinfo("Success", "Registration successful")
                client_id = login_client(username, password)
                
                username_entry.delete(0, ctk.END)
                username_entry.insert(0, username)
                password_entry.delete(0, ctk.END)
                password_entry.insert(0, password)
            else:
                messagebox.showerror("Error", "Username already exists")
                return
        else:
            client_id = login_client(username, password)
            if not client_id:
                messagebox.showerror("Error", "Invalid username or password")
                return

        reg_login_window.destroy()
        root.deiconify()

    
    proceed_button = ctk.CTkButton(reg_login_window, text="Login", command=proceed, font=("Courier New", 14), width=100)
    proceed_button.place(x=150, y=360)

    
    ctk.CTkButton(reg_login_window, text="Cancel", command=lambda: [reg_login_window.destroy(), root.destroy()], 
                  font=("Courier New", 14), width=100, hover_color="#f87306" ,fg_color="#FF5733").place(x=30, y=360)
def try_connect(): 
    global client_socket
    try:
        client_socket.connect(("127.0.0.1", 12345))
        client_socket.send("REQUEST_CONNECTION".encode('utf-8'))
        response = client_socket.recv(1024).decode('utf-8', errors='ignore')

        if response == "CONNECTION_ACCEPTED":
            update_status("🟢 Connected", "green")
            log_message("✅ Connected to the server!", "green")
            enable_buttons(True)
            
            
            if client_id is None:
                show_registration_login()
            
            threading.Thread(target=listen_to_server, daemon=True).start()

        elif response == "CONNECTION_REFUSED":
            log_message("❌ Connection refused by the server!", "red")
            enable_buttons(False)
            client_socket.close()
            client_socket = None

        else:
            raise Exception("Unexpected server response!")

    except ConnectionRefusedError:
        log_message("❌ Server is unavailable!", "red")
        messagebox.showerror("Error", "The server is unavailable! Please try again.")
        if client_socket:
            client_socket.close()
            client_socket = None

    except Exception as e:
        log_message(f"⚠️ Connection error: {e}", "red")
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")
        if client_socket:
            client_socket.close()
            client_socket = None


def show_my_files(client_id):
    files = get_client_files(client_id)
    files_window = ctk.CTkToplevel(root)
    files_window.title("My Files")
    files_window.geometry("550x300")
    
    files_window.iconbitmap("icons/client_icon.ico")
    
    files_window.lift() 
    files_window.focus_force()  
    files_window.grab_set()  
   
   
    
    files_text = ctk.CTkTextbox(files_window, width=520, height=280, wrap="word", font=("Courier New", 13))
    files_text.pack(pady=10)

    unique_files = set()

    if files:
        for file in files:
            if file[0] not in unique_files:
                unique_files.add(file[0])
                files_text.insert("end", f"✅ {file[0]} ({file[1]} bytes) - {file[2]}\n\n")
    else:
        files_text.insert("end", "🚫 No files found.")

    files_text.configure(state="disabled")


        
def connect_to_server():
    global client_socket
    
    if client_socket:
        try:
            client_socket.close()
        except:
            pass
    
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    threading.Thread(target=try_connect, daemon=True).start()

def listen_to_server():
    global client_socket
    try:
        while True:
            try:
                data = client_socket.recv(1024).decode('utf-8', errors='ignore')
                if not data:
                    break
                
                if data == "SERVER_STOPPED!":
                    log_message("🔴 The server has been stopped.", "red")
                    update_status("🔴 Disconnected", "red")
                    enable_buttons(False)
                    messagebox.showwarning("Connection Error", "The server connection has been closed.")
                    break
                
                log_message(f"📩 Message from server: {data}", "blue")
                
            except (ConnectionAbortedError, ConnectionResetError):
                log_message("🔴 Connection to the server has been lost.", "red")
                update_status("🔴 Disconnected", "red")
                enable_buttons(False)
                break
            
    except OSError:
        pass    
       
    except Exception as e:
        log_message(f"❌ Listening failed: {e}", "red")
             
    finally:
        if client_socket:
            try:
                client_socket.close()
            except:
                pass
            client_socket = None

def disconnect_from_server():
    global client_socket
    try:
        if client_socket:
            client_socket.send("DISCONNECT".encode('utf-8'))
            client_socket.close()
            client_socket = None
            
        update_status("🔴 Disconnected", "red")
        enable_buttons(False)
        log_message("🔴 Disconnected from the server!", "red")
    except Exception as e:
        log_message(f"❌ Disconnection failed: {e}", "red")
    
def send_text():
    global client_id
    message = text_input.get()
    
    if message:
        try:
            send_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
           
            formatted_message = f"{client_id}:{message}"
            client_socket.send(formatted_message.encode('utf-8'))

            log_message(f"📤 {send_time} | Sent: {message}", "green")
            
           
            text_input.delete(0, ctk.END)
            
        except Exception as e:
            log_message(f"❌ Sending failed: {e}", "red")
def save_message_to_file(username, message):
    
    log_folder = "Messages"
    
    if not os.path.exists(log_folder):
        os.makedirs(log_folder)

    file_path = os.path.join(log_folder, f"{username}_messages.txt")

    with open(file_path, "a", encoding="utf-8") as file:
        file.write(message + "\n")
    
def send_file():
    if not client_id:
        messagebox.showerror("Error", "You must log in first!")
        return

    file_path = filedialog.askopenfilename()
    if file_path:
        try:
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            client_socket.send(f"FILE:{file_name}:{file_size}:{client_id}".encode('utf-8'))

            with open(file_path, "rb") as file:
                while chunk := file.read(1024):
                    client_socket.send(chunk)

            send_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            save_file_info(client_id, file_name, file_size, send_time)

        except Exception as e:
            messagebox.showerror("Error", f"File sending failed: {e}")

def log_message(message, color="black"):
    messages_text.configure(state="normal")
    messages_text.insert("end", message + "\n", color)
    messages_text.configure(state="disabled")
    messages_text.yview("end")

def update_status(status, color):
    client_status.set(status)
    client_status_label.configure(text_color=color)

def enable_buttons(connected):
    send_text_button.configure(state="normal" if connected else "disabled")
    send_file_button.configure(state="normal" if connected else "disabled")
    disconnect_button.configure(state="normal" if connected else "disabled")
    connect_button.configure(state="disabled" if connected else "normal")


def on_closing():
    global client_socket
    try:
        if client_socket:
            client_socket.send("DISCONNECT".encode('utf-8'))
            client_socket.close()
    except:
        pass
    root.destroy()

def clear_log():
    messages_text.configure(state="normal")
    messages_text.delete("1.0", "end")
    messages_text.configure(state="disabled")


root = ctk.CTk()
root.withdraw() 
root.title("TCP Client")
root.geometry("500x500") 
root.configure(bg="#f0f0f0")

root.iconbitmap("icons/client_icon.ico")



menu_bar = Menu(root)
root.config(menu=menu_bar)

file_menu = Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Clear Log", command=clear_log)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=on_closing)
menu_bar.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="Show My Files", command=lambda: show_my_files(client_id))

client_status = ctk.StringVar(value="⚪ Not Connected")

status_frame = ctk.CTkFrame(root)
status_frame.pack(pady=5)

ctk.CTkLabel(status_frame, text="Client status:", font=("courier new", 14, "bold")).pack(side="left", padx=5)
client_status_label = ctk.CTkLabel(status_frame, textvariable=client_status, text_color="gray", font=("courier new", 14, "bold"))
client_status_label.pack(side="left")

button_frame = ctk.CTkFrame(root)
button_frame.pack(pady=10)

connect_button = ctk.CTkButton(button_frame, text="Connect to server", command=connect_to_server, hover_color="#f87306", fg_color="#4CAF50", text_color="white", state="normal")
connect_button.pack(side="left", padx=5)

disconnect_button = ctk.CTkButton(button_frame, text="Disconnect", state="disabled", command=disconnect_from_server, hover_color="#f87306" , fg_color="#f44336", text_color="white")
disconnect_button.pack(side="left", padx=5)


text_input_frame = ctk.CTkFrame(root)
text_input_frame.pack(pady=5)


text_input = ctk.CTkEntry(text_input_frame, width=250, font=("Courier New", 12), placeholder_text="Enter text to send....")
text_input.pack(side="left", padx=5)
text_input.bind("<Return>", lambda event: send_text())

send_text_button = ctk.CTkButton(text_input_frame, text="Send text", state="disabled", command=send_text, hover_color="#f87306" , fg_color="#008CBA", text_color="white", width=65)
send_text_button.pack(side="left", padx=5)


send_file_frame = ctk.CTkFrame(root)
send_file_frame.pack(pady=10)

send_file_button = ctk.CTkButton(send_file_frame, text="Send file", state="disabled", command=send_file, fg_color="#f44336", hover_color="#f87306" ,text_color="white", width=65)
send_file_button.pack()

messages_text = ctk.CTkTextbox(root, width=450, height=300, state="disabled", wrap="word", font=("Courier New", 12))
messages_text.pack(pady=10)
messages_text.tag_config("red", foreground="red")
messages_text.tag_config("green", foreground="green")
messages_text.tag_config("blue", foreground="blue")

root.protocol("WM_DELETE_WINDOW", on_closing)
show_registration_login()
root.mainloop()