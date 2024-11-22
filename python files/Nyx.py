import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.fernet import Fernet
import json
import os
from hashlib import sha256

# Variables globales
activation_code = "0000"
password_file = "nyx_passwords.json"
key_file = "nyx.key"
data_file = "passwords.secure"

# Fonction pour hacher les mots de passe
def hash_password(password):
    return sha256(password.encode()).hexdigest()

# Charger les mots de passe principaux
def load_nyx_passwords():
    if os.path.exists(password_file):
        with open(password_file, "r") as f:
            return json.load(f)
    else:
        # Par défaut : trois mots de passe hachés
        default_passwords = ["password1", "password2", "password3"]
        hashed_defaults = [hash_password(pw) for pw in default_passwords]
        save_nyx_passwords(hashed_defaults)
        return hashed_defaults

# Sauvegarder les mots de passe principaux
def save_nyx_passwords(passwords):
    with open(password_file, "w") as f:
        json.dump(passwords, f)

# Générer une clé de chiffrement si elle n'existe pas
if not os.path.exists(key_file):
    with open(key_file, "wb") as f:
        f.write(Fernet.generate_key())

with open(key_file, "rb") as f:
    encryption_key = f.read()

cipher = Fernet(encryption_key)

# Charger les mots de passe stockés
def load_password_data():
    if not os.path.exists(data_file):
        return []
    with open(data_file, "rb") as f:
        encrypted_data = f.read()
        try:
            decrypted_data = cipher.decrypt(encrypted_data).decode()
            return json.loads(decrypted_data)
        except Exception:
            return []

# Sauvegarder les mots de passe
def save_password_data(data):
    encrypted_data = cipher.encrypt(json.dumps(data).encode())
    with open(data_file, "wb") as f:
        f.write(encrypted_data)

password_data = load_password_data()
stored_passwords = load_nyx_passwords()


class NyxApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Calculatrice scientifique")
        self.root.geometry("400x600")
        self.root.resizable(False, False)
        self.create_calculator()

    def create_calculator(self):
        """Crée une interface élégante pour la calculatrice."""
        frame = ttk.Frame(self.root, padding="10")
        frame.pack(fill="both", expand=True)

        # Entrée
        self.entry = ttk.Entry(frame, font=("Arial", 20), justify="right")
        self.entry.grid(row=0, column=0, columnspan=4, pady=10)

        # Boutons
        buttons = [
            '7', '8', '9', '/', 
            '4', '5', '6', '*', 
            '1', '2', '3', '-', 
            '0', '.', '=', '+', 
            'C'
        ]
        for i, b in enumerate(buttons):
            ttk.Button(frame, text=b, command=lambda b=b: self.button_click(b)).grid(
                row=(i // 4) + 1, column=i % 4, sticky="nsew", padx=5, pady=5
            )

        # Configuration des dimensions dynamiques
        for i in range(5):
            frame.rowconfigure(i, weight=1)
        for i in range(4):
            frame.columnconfigure(i, weight=1)

    def button_click(self, value):
        """Gère les clics des boutons de la calculatrice."""
        if value == "=":
            try:
                result = eval(self.entry.get())
                self.entry.delete(0, tk.END)
                self.entry.insert(0, result)
            except Exception:
                self.entry.delete(0, tk.END)
                self.entry.insert(0, "Erreur")
        elif value == "C":
            self.entry.delete(0, tk.END)
        else:
            self.entry.insert(tk.END, value)

        # Vérification du code d'activation
        if self.entry.get() == activation_code:
            self.root.destroy()
            self.launch_nyx()

    def launch_nyx(self):
        """Lance l'application Nyx."""
        nyx_root = tk.Tk()
        nyx_root.title("Nyx - Gestionnaire de mots de passe")
        nyx_root.geometry("800x600")
        Nyx(nyx_root)
        nyx_root.mainloop()


class Nyx:
    def __init__(self, root):
        self.root = root

        # Interface principale
        frame = ttk.Frame(self.root, padding=20)
        frame.pack(fill="both", expand=True)

        ttk.Label(frame, text="Entrez les 3 mots de passe pour accéder :", font=("Arial", 14)).pack(pady=20)

        self.password_entries = []
        for i in range(3):
            entry = ttk.Entry(frame, show="*", font=("Arial", 14), width=30)
            entry.pack(pady=5)
            self.password_entries.append(entry)

        ttk.Button(frame, text="Valider", command=self.validate_passwords).pack(pady=20)

    def validate_passwords(self):
        """Vérifie les mots de passe saisis par l'utilisateur."""
        input_passwords = [hash_password(entry.get()) for entry in self.password_entries]

        if input_passwords == stored_passwords:
            self.launch_password_manager()
        else:
            messagebox.showerror("Erreur", "Mots de passe incorrects.")

    def launch_password_manager(self):
        """Lance l'interface du gestionnaire de mots de passe."""
        for widget in self.root.winfo_children():
            widget.destroy()

        ttk.Label(self.root, text="Gestionnaire de mots de passe", font=("Arial", 16)).pack(pady=20)

        # Liste des mots de passe
        self.tree = ttk.Treeview(self.root, columns=("Sujet", "Mot de passe"), show="headings")
        self.tree.heading("Sujet", text="Sujet")
        self.tree.heading("Mot de passe", text="Mot de passe")
        self.tree.pack(fill="both", expand=True, pady=10)

        # Ajouter les données initiales
        self.update_password_list()

        # Boutons d'action
        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=10)
        ttk.Button(button_frame, text="Ajouter", command=self.add_password).grid(row=0, column=0, padx=5)
        ttk.Button(button_frame, text="Modifier", command=self.edit_password).grid(row=0, column=1, padx=5)
        ttk.Button(button_frame, text="Supprimer", command=self.delete_password).grid(row=0, column=2, padx=5)

    def update_password_list(self):
        """Met à jour la liste affichée."""
        for row in self.tree.get_children():
            self.tree.delete(row)
        for entry in password_data:
            self.tree.insert("", "end", values=(entry["Sujet"], entry["Mot de passe"]))

    # Les fonctions `add_password`, `edit_password`, et `delete_password` restent inchangées.


    def add_password(self):
        """Ajoute un mot de passe."""
        self.open_password_editor("Ajouter un mot de passe", None)

    def edit_password(self):
        """Modifie un mot de passe existant."""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Erreur", "Veuillez sélectionner un mot de passe à modifier.")
            return
        item_data = self.tree.item(selected_item)["values"]
        self.open_password_editor("Modifier un mot de passe", item_data)

    def delete_password(self):
        """Supprime un mot de passe."""
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Erreur", "Veuillez sélectionner un mot de passe à supprimer.")
            return

        item_data = self.tree.item(selected_item)["values"]
    
        # Demander confirmation
        confirmation = messagebox.askyesno(
            "Confirmation",
            f"Êtes-vous sûr de vouloir supprimer le mot de passe pour '{item_data[0]}' ?"
        )
    
        if confirmation:
            for entry in password_data:
                if entry["Sujet"] == item_data[0] and entry["Mot de passe"] == item_data[1]:
                    password_data.remove(entry)
                    break
            save_password_data(password_data)
            self.update_password_list()
            messagebox.showinfo("Succès", f"Le mot de passe pour '{item_data[0]}' a été supprimé.")


    def open_password_editor(self, title, data):
        """Ouvre une fenêtre pour ajouter ou modifier un mot de passe."""
        editor = tk.Toplevel(self.root)
        editor.title(title)
        editor.geometry("400x200")

        ttk.Label(editor, text="Sujet :", font=("Arial", 12)).pack(pady=5)
        sujet_entry = ttk.Entry(editor, font=("Arial", 12))
        sujet_entry.pack(pady=5)
        if data:
            sujet_entry.insert(0, data[0])

        ttk.Label(editor, text="Mot de passe :", font=("Arial", 12)).pack(pady=5)
        password_entry = ttk.Entry(editor, font=("Arial", 12))
        password_entry.pack(pady=5)

        def save_data():
            sujet = sujet_entry.get()
            mot_de_passe = password_entry.get()
            if not sujet or not mot_de_passe:
                messagebox.showerror("Erreur", "Tous les champs sont obligatoires.")
                return

            if data:
                for entry in password_data:
                    if entry["Sujet"] == data[0] and entry["Mot de passe"] == data[1]:
                        entry["Sujet"] = sujet
                        entry["Mot de passe"] = mot_de_passe
                        break
            else:
                password_data.append({"Sujet": sujet, "Mot de passe": mot_de_passe})
            save_password_data(password_data)
            self.update_password_list()
            editor.destroy()

        ttk.Button(editor, text="Enregistrer", command=save_data).pack(pady=10)


if __name__ == "__main__":
    root = tk.Tk()
    app = NyxApp(root)
    root.mainloop()
