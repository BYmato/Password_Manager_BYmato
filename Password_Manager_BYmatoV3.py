import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog
import customtkinter
from functools import partial
import uuid
import pyperclip
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

backend = default_backend()
salt = b'2444'


def kdf():
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=backend)

encryption_key = 0


def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)


def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)


# Database Code
with sqlite3.connect("password_vault.db") as db:
    cursor = db.cursor()

# Master Password data
cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL,
recovery_key TEXT NOT NULL);
""")

# Vault data
cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
""")

# Pop Up Window


def pop_up(text):
    popup_input = simpledialog.askstring("Password Vault", text)
    return popup_input


# Main Window

window = customtkinter.CTk()
window.update()

window.title("Password Vault")


# Hash Password

def hash_password(input):
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()

    return hash


# Vault Password Creation Functions

def login_creation():
    cursor.execute('DELETE FROM vault')

    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("300x200")
    # Create Master password label
    login_create_label = customtkinter.CTkLabel(window, text="Create Your Password")
    login_create_label.configure(anchor=CENTER)
    login_create_label.pack()

    # Master Password Input
    login_create_input = customtkinter.CTkEntry(window, width=200)
    login_create_input.focus()
    login_create_input.pack()

    # Confirm Master Password label
    login_create_label_check = customtkinter.CTkLabel(window, text="Confirm Your Password")
    login_create_label_check.pack()

    # Confirm Master password input
    login_create_input_check = customtkinter.CTkEntry(window, width=200)
    login_create_input_check.pack()

    # Error for Passwords not matching
    login_password_match_error = customtkinter.CTkLabel(window, text=" ")
    login_password_match_error.configure(anchor=CENTER)
    login_password_match_error.pack()

    def master_password_save():
        if login_create_input.get() == login_create_input_check.get():
            sql = "DELETE FROM masterpassword WHERE id = 1"

            cursor.execute(sql)

            hashed_password = hash_password(login_create_input.get().encode('utf-8'))
            key = str(uuid.uuid4().hex)
            recovery_key = hash_password(key.encode('utf-8'))

            global encryption_key
            encryption_key = base64.urlsafe_b64encode(kdf().derive(login_create_input.get().encode()))

            insert_password = """INSERT INTO masterpassword(password, recovery_key)
            VALUES(?, ?)"""
            cursor.execute(insert_password, ((hashed_password), (recovery_key)))
            db.commit()

            recovery_screen(key)
        else:
            login_password_match_error.configure(text="Passwords do not match!")

    # Save Button
    login_button = customtkinter.CTkButton(window, text="Save", command=master_password_save)
    login_button.pack(pady=10)


# Recovery Window

def recovery_screen(key):
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x150")
    # Recovery Label Text
    recovery_label = customtkinter.CTkLabel(window, text="Save this key to recover your account")
    recovery_label.configure(anchor=CENTER)
    recovery_label.pack()
    # Recovery Key Label
    recovery_label_key = customtkinter.CTkLabel(window, text=key)
    recovery_label_key.configure(anchor=CENTER)
    recovery_label_key.pack()

    def copy_recovery_key():
        pyperclip.copy(recovery_label_key.cget("text"))

    copy_recovery_key_button = customtkinter.CTkButton(window, text="Copy", command=copy_recovery_key)
    copy_recovery_key_button.pack(pady=5)

    def continue_button():
        password_vault()

    continue_button = customtkinter.CTkButton(window, text="Continue", command=continue_button)
    continue_button.pack(pady=5)


# Reset Login Password

def reset_screen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x175")
    # Recovery Label
    reset_input_label = customtkinter.CTkLabel(window, text="Enter your Recovery Key")
    reset_input_label.configure(anchor=CENTER)
    reset_input_label.pack()
    # Recovery Key Input
    recovery_key_input = customtkinter.CTkEntry(window, width=200)
    recovery_key_input.pack()
    recovery_key_input.focus()
    # Recovery Wrong Key label
    recovery_wrong_key_label = customtkinter.CTkLabel(window, text=" ")
    recovery_wrong_key_label.configure(anchor=CENTER)
    recovery_wrong_key_label.pack()

    # Check Recovery key Function
    def get_recovery_key():
        recovery_key_check = hash_password(str(recovery_key_input.get()).encode('utf-8'))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 AND recovery_key = ?", [(recovery_key_check)])
        return cursor.fetchall()

    # Check Recovery Button Function
    def recovery_key_checker():
        checked = get_recovery_key()

        if checked:
            login_creation()
        else:
            recovery_key_input.delete(0, END)
            recovery_wrong_key_label.configure(text="Wrong Recovery Key")

    # Check Recovery Key Button
    check_recovery_button = customtkinter.CTkButton(window, text="Check Key", command=recovery_key_checker)
    check_recovery_button.pack(pady=5)


# Login Window, Functions

def login_screen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("250x150")

    login_label = customtkinter.CTkLabel(window, text="Enter your Password")
    login_label.configure(anchor=CENTER)
    login_label.pack()
    # User Input
    login_input = customtkinter.CTkEntry(window, width=200)
    login_input.configure(show="*")
    login_input.pack()

    def get_master_password():
        checkhashedpassword = hash_password(login_input.get().encode('utf-8'))
        global encryption_key
        encryption_key = base64.urlsafe_b64encode(kdf().derive(login_input.get().encode()))
        cursor.execute("SELECT * FROM masterpassword WHERE id = 1 and password = ?", [(checkhashedpassword)])
        return cursor.fetchall()

    def log_in_password_check():
        master_password = get_master_password()

        if master_password:
            password_vault()
        else:
            login_input.delete(0, END)
            login_label.configure(text="Wrong password")

    # Reset Button/Function
    def reset_login_password():
        reset_screen()

    # Enter Button
    login_button = customtkinter.CTkButton(window, text="Enter", command=log_in_password_check)
    login_button.pack(pady=10)
    # Reset Button
    login_button = customtkinter.CTkButton(window, text="Reset Password", command=reset_login_password)
    login_button.pack(pady=10)


# Password Vault

def password_vault():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("350x250")

    # Scrollable Frame
    scrollable_frame = customtkinter.CTkScrollableFrame(window)
    scrollable_frame.pack(fill="both", expand=True)


    # Adding Entries Function
    def add_entry_categories():
        website_entry = "Website"
        username_entry = "Username"
        password_entry = "Password"

        website_input = encrypt(pop_up(website_entry).encode(), encryption_key)
        username_input = encrypt(pop_up(username_entry).encode(), encryption_key)
        password_input = encrypt(pop_up(password_entry).encode(), encryption_key)

        insert_fields = """INSERT INTO vault(website,username,password)
        VALUES(?, ?, ?)"""

        cursor.execute(insert_fields, (website_input, username_input, password_input))
        db.commit()

        password_vault()

    # Removing Entries Function
    def remove_entry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()

        password_vault()

    # Vault Welcome Label
    vault_label = customtkinter.CTkLabel(scrollable_frame, text="Your personal Password Vault")
    vault_label.configure(anchor=CENTER)
    vault_label.grid(column=1)

    # ADD Button
    add_button = customtkinter.CTkButton(scrollable_frame, text="ADD NEW", command=add_entry_categories)
    add_button.grid(row=1, column=1, pady=10, ipadx=20)

    # Category Labels
    website_label = customtkinter.CTkLabel(scrollable_frame, text="Website")
    website_label.grid(row=2, column=0, padx=80)
    username_label = customtkinter.CTkLabel(scrollable_frame, text="Username")
    username_label.grid(row=2, column=1, padx=80)
    password_label = customtkinter.CTkLabel(scrollable_frame, text="Password")
    password_label.grid(row=2, column=2, padx=80)

    # Rows adding and deleting
    cursor.execute("SELECT * FROM vault")
    if (cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute("SELECT * FROM vault")
            array = cursor.fetchall()

            if (len(array) == 0):
                break

            website_row = customtkinter.CTkLabel(scrollable_frame, text=(decrypt(array[i][1], encryption_key)))
            website_row_copy = customtkinter.CTkEntry(scrollable_frame, fg_color="transparent", border_width=0)
            website_row_copy.insert(0, website_row.cget("text"))
            website_row_copy.configure(state="readonly")
            website_row_copy.grid(column=0, row=i + 3)
            username_row = customtkinter.CTkLabel(scrollable_frame, text=(decrypt(array[i][2], encryption_key)))
            username_row_copy = customtkinter.CTkEntry(scrollable_frame, fg_color="transparent", border_width=0)
            username_row_copy.insert(0, username_row.cget("text"))
            username_row_copy.configure(state="readonly")
            username_row_copy.grid(column=1, row=i + 3)
            password_row = customtkinter.CTkLabel(scrollable_frame, text=(decrypt(array[i][3], encryption_key)))
            password_row_copy = customtkinter.CTkEntry(scrollable_frame, fg_color="transparent", border_width=0)
            password_row_copy.insert(0, password_row.cget("text"))
            password_row_copy.configure(state="readonly")
            password_row_copy.grid(column=2, row=i + 3)
            # Delete Button
            delete_button = customtkinter.CTkButton(scrollable_frame, text="Delete", command=partial(remove_entry, array[i][0]))
            delete_button.grid(column=3, row=i + 3, pady=5, padx=5)

            i = i + 1

            cursor.execute("SELECT * FROM vault")
            if (len(cursor.fetchall())) <= i:
                break


# Login Check

cursor.execute("SELECT * FROM masterpassword")
if cursor.fetchall():
    login_screen()
else:
    login_creation()

# Main Window Loop

window.mainloop()