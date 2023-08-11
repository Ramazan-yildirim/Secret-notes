from tkinter import *
from tkinter import messagebox
import base64


def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


def save_notes():
    title = title_entry.get()
    message = input_text.get("1.0", END)
    secret = secret_entry.get()

    if len(title) == 0 or len(message) == 0 or len(secret) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all info.")
    else:
        message_encrypted = encode(secret, message)
        try:
            with open("mysecret.txt", "a") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        except FileNotFoundError:
            with open("mysecret.txt", "w") as data_file:
                data_file.write(f"\n{title}\n{message_encrypted}")
        finally:
            title_entry.delete(0, END)
            input_text.delete("1.0", END)
            secret_entry.delete(0, END)


def decryp_notes():
    message_decryp = input_text.get("1.0", END)
    secret_decryp = secret_entry.get()

    if len(message_decryp) == 0 or len(secret_decryp) == 0:
        messagebox.showinfo(title="Error!", message="Please enter all info.")
    else:
        try:
            decrypted_message = decode(secret_decryp, message_decryp)
            input_text.delete("1.0", END)
            input_text.insert("1.0", decrypted_message)
        except:
            messagebox.showinfo(title="Error!", message="Please enter encrypted text!.")


FONT = ("verdana", 13, "normal")
window = Tk()
window.title("Secret Notes")
window.config(padx=30, pady=30)

photo = PhotoImage(file="secretlogo.png")
photo_lable = Label(image=photo)
photo_lable.pack()

title_lable = Label(text="Enter your title", font=FONT)
title_lable.pack()

title_entry = Entry(width=30)
title_entry.pack()

text_lable = Label(text="Enter your text", font=FONT)
text_lable.pack()

input_text = Text(width=30, height=17)
input_text.pack()

secret_lable = Label(text="Enter master key", font=FONT)
secret_lable.pack()

secret_entry = Entry(width=30)
secret_entry.pack()

save_button = Button(text="Save & Encrypt", command=save_notes)
save_button.pack()

decryp_button = Button(text="Decrypt", command=decryp_notes)
decryp_button.pack()

window.mainloop()
