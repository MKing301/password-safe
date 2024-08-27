import os
import datetime
import random
import pyperclip
import json

from string import ascii_letters, digits, ascii_lowercase, ascii_uppercase
from tkinter import * # all classes
from tkinter import messagebox # module not imported in class import
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# DEBUG
from rich.traceback import install
from rich.console import Console

install()
console = Console()

ALLOWED_SPECIAL_CHARACTERS = '!$=#'
PASSWORD = b"arewehavingfunyet"
SALT = os.urandom(16)
KDF = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=SALT,
    iterations=480000,
)


# ---------------------------- SEARCH ----------------------------------- #

def find_password():
    # Get user's input
    website = website_input.get().title()

    if len(website) == 0:
        messagebox.showwarning(
            title='Warning',
            message='Please populate the Website field!'
        )

    else:

        try:
            # Open file and read data
            with open('data.json', 'r') as data_file:
                data = json.load(data_file)
        except FileNotFoundError:
            messagebox.showerror(
                title='No Records', message='You have not saved any passwords.'
            )
        else:
            if website in data:
                email = data[website]['email']
                password = data[website]['password']
                messagebox.showinfo(
                    title='Credentials',
                    message=f'Email: {email}\nPassword: {password}'
                )
            else:
                messagebox.showwarning(
                    title='Warning',
                    message=f'{website} not found!'
                )
        finally:
            # Clear website field
            website_input.delete(0, END)


# ---------------------------- PASSWORD GENERATOR -------------------------- #


def get_random_password():

    random_source = ascii_letters + digits + ALLOWED_SPECIAL_CHARACTERS
    # select 1 lowercase
    password = random.choice(ascii_lowercase)
    # select 1 uppercase
    password += random.choice(ascii_uppercase)
    # select 1 digit
    password += random.choice(digits)
    # select 1 special symbol
    password += random.choice(ALLOWED_SPECIAL_CHARACTERS)

    # generate other characters 8 characters
    for i in range(12):
        password += random.choice(random_source)

    password_list = list(password)
    # shuffle all characters
    random.SystemRandom().shuffle(password_list)

    # Both pass gen works with code below
    generated_password = ''.join(password_list)

    console.print(f'Generated Password: {generated_password}\n')  # DEBUG

    #  key = {'k': base64.urlsafe_b64encode(kdf.derive(password))}
    key = b'-80UDkN8b_glCvgStgf5LuRgUWm2HaKZXK9xLlIdzio='
    f = Fernet(key)
    encpass = f.encrypt(f'Encrypted Password: {generated_password}'.encode('utf-8'))

    console.print(encpass) # DEBUG
    password_input.insert(0, generated_password)
    pyperclip.copy(generated_password)

# ---------------------------- SAVE PASSWORD ------------------------------- #


def save():

    # Fetch input text
    website = website_input.get()
    email = email_input.get()
    password = password_input.get()

    new_data = {
        website.title(): {
            "email": email,
            "password": password,
        }
    }

    if len(website) < 1 or len(password) < 1:
        messagebox.showwarning(
            title='Missing Input(s)',
            message='Please do not leave any inputs empty!'
        )

    else:
        # Check details
        is_ok = messagebox.askokcancel(
            title='website',
            message=(
                f'There are the details you entered:\nEmail: {email}\n'
                f'Password: {password}\n\nIs it ok to save?'
            )
        )

        if is_ok:

            try:
                # Open file
                with open('data.json', 'r') as data_file:
                    # Read existing data
                    data = json.load(data_file)
            except FileNotFoundError:
                # File not found, create file
                with open('data.json', 'w') as data_file:
                    # Write new data to file
                    json.dump(new_data, data_file, indent=4)
            else:
                # Update file with new data
                data.update(new_data)

                with open('data.json', 'w') as data_file:
                    # Saving updated data
                    json.dump(new_data, data_file, indent=4)
            finally:
                # Clear website and password fields
                website_input.delete(0, END)
                password_input.delete(0, END)


# ---------------------------- UI SETUP ----------------------------------- #

# Create window
window = Tk()
window.title('Password Manager')
window.config(padx=50, pady=50)

# Create canvas
canvas = Canvas(height=200, width=200)
logo_img = PhotoImage(file='logo.png')
canvas.create_image(100, 100, image=logo_img)
canvas.grid(row=0, column=1)

# Labels
website_label = Label(text='Website:')
website_label.grid(row=1, column=0, pady=2)

email_label = Label(text='Email/Username:')
email_label.grid(row=2, column=0, pady=2)

password_label = Label(text='Password:')
password_label.grid(row=3, column=0, pady=2)

# Inputs
website_input = Entry(width=34)
website_input.grid(row=1, column=1, pady=2)
website_input.focus() # Start with cursor in website input box

email_input = Entry(width=53)
email_input.grid(row=2, column=1, columnspan=3, pady=2)
email_input.insert(index=0, string='first_name.last_name@nc.gov')

password_input = Entry(width=34)
password_input.grid(row=3, column=1, pady=2)

# Buttons
generate_password_button = Button(
    text='Generate Password', command=get_random_password
)
generate_password_button.grid(row=3, column=2, pady=2)

search_button = Button(
    text='Search', width=14, command=find_password
)
search_button.grid(row=1, column=2, pady=2)

add_button = Button(text='Add', width=45, command=save)
add_button.grid(row=4, column=1, columnspan=2, pady=2)

window.mainloop()
