import socket
import threading
import os
import customtkinter as ctk

from tkinter import  messagebox, Menu, PhotoImage
from datetime import datetime
from database import save_file_info, get_username_by_id


if not os.path.exists("received_files"):
    os.makedirs("received_files")
server_socket = None
clients = []
server_running = True

ctk.set_appearance_mode("light")  
ctk.set_default_color_theme("green")  

def handle_client(client_socket, address):
    
    log_message(f"🔗 New connection from {address}", "blue")

    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            
            decoded_data = data.decode('utf-8', errors='ignore')

            if decoded_data == "DISCONNECT":
                log_message(f"🚫 Client {address} disconnected.", "red")
                break

            if decoded_data == "REQUEST_CONNECTION":
                continue

            receive_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            if decoded_data.startswith("FILE:"):
                file_info = decoded_data.split(":")
                
                if len(file_info) < 4:
                    log_message(f"⚠️ Invalid file data from {address}", "red")
                    client_socket.send("ERROR: Invalid file data".encode('utf-8'))
                    continue
                
                file_name, file_size, client_id = file_info[1], file_info[2], file_info[3]

                try:
                    file_size = int(file_size)
                    client_id = int(client_id)
                except ValueError:
                    log_message(f"⚠️ Invalid file size or client ID from {address}", "red")
                    client_socket.send("ERROR: Invalid file size or client ID".encode('utf-8'))
                    continue

                # استرجاع اسم المستخدم
                username = get_username_by_id(client_id)
                if not username:
                    log_message(f"❌ Unauthorized file upload attempt by {address}", "red")
                    client_socket.send("ERROR: Unauthorized client ID".encode('utf-8'))
                    continue

                log_message(f"📩 Receiving file: {file_name} ({file_size} bytes) from {username}", "blue")

                file_path = os.path.join("received_files", file_name)
                with open(file_path, "wb") as file:
                    received_bytes = 0
                    while received_bytes < file_size:
                        chunk = client_socket.recv(min(4096, file_size - received_bytes))
                        file.write(chunk)
                        received_bytes += len(chunk)

                receive_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log_message(f"✅ {receive_time} | File received: {file_name} from {username}", "green")
                save_file_info(client_id, file_name, file_size, receive_time)
                client_socket.send("FILE_RECEIVED".encode('utf-8'))

            else:  # معالجة الرسائل النصية
                try:
                    client_id, message = decoded_data.split(":", 1)
                    client_id = int(client_id)
                    username = get_username_by_id(client_id)

                    if username:
                        log_message(f"📩 {receive_time} | {username}: {message}", "blue")
                        
                        # ✅ حفظ الرسالة في ملف العميل
                        save_message_to_file(username, f"{receive_time} | {message}")

                        client_socket.send("Message received ✅".encode('utf-8'))
                    else:
                        log_message(f"⚠️ Unrecognized client ID: {client_id}", "red")
                        client_socket.send("ERROR: Unrecognized client ID".encode('utf-8'))
                except ValueError:
                    log_message(f"⚠️ Invalid message format from {address}", "red")
                    client_socket.send("ERROR: Invalid message format".encode('utf-8'))

    except ConnectionResetError:
        log_message(f"❌ Connection reset by {address}.", "red")

    except OSError as e:
        if server_running:
            log_message(f"⚠️ Error with {address}: {e}", "red")

    finally:
        client_socket.close()
        if client_socket in clients:
            clients.remove(client_socket)

        log_message(f"❌ Connection closed: {address}", "red")

def save_message_to_file(username, message):
    
    log_folder = "Messages"

    if not os.path.exists(log_folder):
        os.makedirs(log_folder)

    file_path = os.path.join(log_folder, f"{username}_messages.txt")

    with open(file_path, "a", encoding="utf-8") as file:
        file.write(message + "\n")

def start_server():
    global server_socket, server_running

    if server_socket:
        server_socket.close()
    
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("0.0.0.0", 12345))
    server_socket.listen(5)

    server_running = True
    server_status.set("🟢 Connected")
    server_status_label.configure(text_color="green")

    # تعطيل زر تشغيل السيرفر وتفعيل زر الإيقاف
    start_button.configure(state="disabled")
    stop_button.configure(state="normal")

    log_message("🚀 Server is running and waiting for connections...", "green")

    while server_running:
        try:
            client_socket, client_address = server_socket.accept()
            response = messagebox.askyesno("Connection Request", f"Do you accept the connection from {client_address}?")
            if response:
                client_socket.send("CONNECTION_ACCEPTED".encode('UTF-8'))
                clients.append(client_socket)
                threading.Thread(target=handle_client, args=(client_socket, client_address), daemon=True).start()
                log_message(f"✅ Connection from {client_address} accepted.", "green")
            else:
                client_socket.send("CONNECTION_REFUSED".encode('UTF-8'))
                client_socket.close()
                log_message(f"❌ Connection from {client_address} was rejected.", "red")

        except Exception as e:
            if server_running:
                log_message(f"⚠️ Server error: {e}", "red")
            break

def stop_server():
    global server_running, server_socket
    server_running = False
    server_status.set("🔴 Disconnected")
    server_status_label.configure(text_color="red")

    start_button.configure(state="normal")
    stop_button.configure(state="disabled")

    log_message("🛑 Server has been stopped!", "red")

    for client in clients[:]:
        try:
            client.send("SERVER_STOPPED!".encode('utf-8'))
            client.close()
        except:
            pass
        finally:
            if client in clients:
                clients.remove(client)

    if server_socket:
        server_socket.close()
        server_socket = None

    log_message("✅ All connections have been terminated.", "green")

def log_message(message, color="black"):
    log_area.configure(state="normal")
    log_area.insert("end", message + "\n", color)
    log_area.configure(state="disabled")
    log_area.yview("end")

def clear_log():
    log_area.configure(state="normal")
    log_area.delete("1.0", "end")
    log_area.configure(state="disabled")

# إنشاء واجهة المستخدم
root = ctk.CTk()
root.title("TCP Server")
root.geometry("500x500")  
root.configure(bg="#f0f0f0")

root.iconbitmap("icons/server_icon.ico")


menu_bar = Menu(root)
root.config(menu=menu_bar)

file_menu = Menu(menu_bar, tearoff=0)
file_menu.add_command(label="Clear Log", command=clear_log)
file_menu.add_separator()
file_menu.add_command(label="Exit", command=root.destroy)
menu_bar.add_cascade(label="File", menu=file_menu)

server_status = ctk.StringVar(value="⚪ Not Connected")

status_frame = ctk.CTkFrame(root)
status_frame.pack(pady=5)

ctk.CTkLabel(status_frame, text="Server status:", font=("courier new", 14, "bold")).pack(side="left", padx=5)
server_status_label = ctk.CTkLabel(status_frame, textvariable=server_status, text_color="gray", font=("courier new", 14, "bold"))
server_status_label.pack(side="left")

button_frame = ctk.CTkFrame(root)
button_frame.pack(pady=10)

start_button = ctk.CTkButton(button_frame, text="Start server", command=lambda: threading.Thread(target=start_server, daemon=True).start(), hover_color="#f87306",fg_color="#4CAF50", text_color="white", state="normal", width=80, height=30)
start_button.pack(side="left", padx=5)

stop_button = ctk.CTkButton(button_frame, text="Stop server", command=stop_server, hover_color="#f87306", fg_color="#f44336", text_color="white", state="disabled",width=80, height=30)
stop_button.pack(side="left", padx=5)


log_area = ctk.CTkTextbox(root, width=450, height=300, state="disabled", wrap="word", font=("courier new", 12))
log_area.pack(pady=10)
log_area.tag_config("red", foreground="red")
log_area.tag_config("green", foreground="green")
log_area.tag_config("blue", foreground="blue")

root.mainloop()