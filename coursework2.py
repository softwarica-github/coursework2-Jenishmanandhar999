from tkinter import *
from tkinter import filedialog
from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key()

def save_key(key, filename):
    with open(filename, 'wb') as f:
        f.write(key)

def load_key(filename):
    with open(filename, 'rb') as f:
        return f.read()

def encrypt_file(key, input_file, output_file):
    fernet = Fernet(key)
    with open(input_file, 'rb') as f:
        data = f.read()
    encrypted_data = fernet.encrypt(data)
    with open(output_file, 'wb') as f:
        f.write(encrypted_data)
    status_label.config(text="File encrypted successfully!")

def decrypt_file(key, input_file, output_file):
    fernet = Fernet(key)
    with open(input_file, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = fernet.decrypt(encrypted_data)
    with open(output_file, 'wb') as f:
        f.write(decrypted_data)
    status_label.config(text="File decrypted successfully!")

def browse_file(entry):
    filename = filedialog.askopenfilename()
    entry.delete(0, END)
    entry.insert(0, filename)

def browse_save_location(entry):
    filename = filedialog.asksaveasfilename()
    entry.delete(0, END)
    entry.insert(0, filename)

def encrypt():
    key = generate_key()
    save_key(key, 'key.key')
    encrypt_file(key, input_entry.get(), output_entry.get())

def decrypt():
    key = load_key('key.key')
    decrypt_file(key, input_entry.get(), output_entry.get())

# Create GUI
root = Tk()
root.title("File Encryption/Decryption")

input_label = Label(root, text="Input File:")
input_label.grid(row=0, column=0, padx=5, pady=5, sticky=E)

input_entry = Entry(root, width=40)
input_entry.grid(row=0, column=1, columnspan=2, padx=5, pady=5)

browse_button = Button(root, text="Browse", command=lambda: browse_file(input_entry))
browse_button.grid(row=0, column=3, padx=5, pady=5)

output_label = Label(root, text="Output File:")
output_label.grid(row=1, column=0, padx=5, pady=5, sticky=E)

output_entry = Entry(root, width=40)
output_entry.grid(row=1, column=1, columnspan=2, padx=5, pady=5)

browse_save_button = Button(root, text="Browse", command=lambda: browse_save_location(output_entry))
browse_save_button.grid(row=1, column=3, padx=5, pady=5)

encrypt_button = Button(root, text="Encrypt", command=encrypt)
encrypt_button.grid(row=2, column=1, padx=5, pady=5)

decrypt_button = Button(root, text="Decrypt", command=decrypt)
decrypt_button.grid(row=2, column=2, padx=5, pady=5)

status_label = Label(root, text="")
status_label.grid(row=3, column=0, columnspan=4, padx=5, pady=5)

root.mainloop()
