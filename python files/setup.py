import os
import json
from hashlib import sha256
from cryptography.fernet import Fernet
from tkinter import Tk, Label, Entry, Button, messagebox

key_file = "nyx.key"
data_file = "passwords.secure"
password_file = "nyx_passwords.json"

# Charger la clé existante ou en créer une nouvelle
if not os.path.exists(key_file):
    with open(key_file, "wb") as f:
        f.write(Fernet.generate_key())

with open(key_file, "rb") as f:
    encryption_key = f.read()

cipher = Fernet(encryption_key)

# Réinitialiser les données sécurisées
def reset_secure_data():
    with open(data_file, "wb") as f:
        f.write(cipher.encrypt(json.dumps([]).encode()))

# Hacher un mot de passe
def hash_password(password):
    return sha256(password.encode()).hexdigest()

# Sauvegarder les mots de passe principaux
def save_nyx_passwords(passwords):
    hashed_passwords = [hash_password(pw) for pw in passwords]
    with open(password_file, "w") as f:
        json.dump(hashed_passwords, f)

# Charger les mots de passe principaux
def load_nyx_passwords():
    if os.path.exists(password_file):
        with open(password_file, "r") as f:
            return json.load(f)
    else:
        return []

# Fenêtre de configuration
def setup_nyx_passwords():
    def validate_and_save():
        pw1 = entry1.get()
        pw2 = entry2.get()
        pw3 = entry3.get()

        if not pw1 or not pw2 or not pw3:
            messagebox.showerror("Erreur", "Tous les champs doivent être remplis.")
            return

        if pw1 == pw2 or pw2 == pw3 or pw1 == pw3:
            messagebox.showerror("Erreur", "Les mots de passe doivent être uniques.")
            return

        # Sauvegarder les nouveaux mots de passe hachés
        save_nyx_passwords([pw1, pw2, pw3])

        # Réinitialiser les données sécurisées
        reset_secure_data()

        messagebox.showinfo("Succès", "Les mots de passe ont été configurés avec succès.")
        root.destroy()

    root = Tk()
    root.title("Configuration des mots de passe Nyx")
    root.geometry("400x300")
    root.resizable(False, False)

    Label(root, text="Configurer les mots de passe pour Nyx", font=("Arial", 14)).pack(pady=10)
    Label(root, text="Mot de passe 1 :", font=("Arial", 12)).pack(pady=5)
    entry1 = Entry(root, show="*", font=("Arial", 12))
    entry1.pack(pady=5)

    Label(root, text="Mot de passe 2 :", font=("Arial", 12)).pack(pady=5)
    entry2 = Entry(root, show="*", font=("Arial", 12))
    entry2.pack(pady=5)

    Label(root, text="Mot de passe 3 :", font=("Arial", 12)).pack(pady=5)
    entry3 = Entry(root, show="*", font=("Arial", 12))
    entry3.pack(pady=5)

    Button(root, text="Enregistrer", command=validate_and_save, font=("Arial", 12)).pack(pady=20)
    root.mainloop()

if __name__ == "__main__":
    setup_nyx_passwords()
