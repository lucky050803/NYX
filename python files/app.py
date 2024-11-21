import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

# Variables globales
activation_code = "0000"
passwords = ["password1", "password2", "password3"]

# Classe principale
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
        nyx_root.title("Nyx - Gestionnaire et Outil de Chiffrement")
        nyx_root.geometry("800x600")
        nyx_root.resizable(False, False)
        Nyx(nyx_root)
        nyx_root.mainloop()


class Nyx:
    def __init__(self, root):
        self.root = root

        # Création des onglets
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True)

        # Onglet Gestionnaire de mots de passe
        password_tab = ttk.Frame(notebook)
        notebook.add(password_tab, text="Gestionnaire de mots de passe")
        self.create_password_manager(password_tab)

        # Onglet Chiffrement/Déchiffrement
        crypto_tab = ttk.Frame(notebook)
        notebook.add(crypto_tab, text="Chiffrement/Déchiffrement")
        self.create_crypto_tool(crypto_tab)

    def create_password_manager(self, frame):
        """Crée l'interface du gestionnaire de mots de passe."""
        ttk.Label(frame, text="Entrez les 3 mots de passe pour accéder :", font=("Arial", 14)).pack(pady=20)

        self.password_entries = []
        for i in range(3):
            entry = ttk.Entry(frame, show="*", width=30)
            entry.pack(pady=5)
            self.password_entries.append(entry)

        ttk.Button(frame, text="Valider", command=self.validate_passwords).pack(pady=20)

    def validate_passwords(self):
        """Vérifie les mots de passe."""
        input_passwords = [entry.get() for entry in self.password_entries]
        if input_passwords == passwords:
            messagebox.showinfo("Succès", "Accès accordé.")
        else:
            messagebox.showerror("Erreur", "Mots de passe incorrects.")

    def create_crypto_tool(self, frame):
        """Crée l'interface de l'outil de chiffrement/déchiffrement."""
        ttk.Label(frame, text="Clé de chiffrement/déchiffrement :", font=("Arial", 14)).pack(pady=10)
        self.key_entry = ttk.Entry(frame, width=50, show="*")
        self.key_entry.pack(pady=5)

        ttk.Label(frame, text="Chemin du fichier :", font=("Arial", 14)).pack(pady=10)
        self.file_entry = ttk.Entry(frame, width=50)
        self.file_entry.pack(pady=5)
        ttk.Button(frame, text="Parcourir", command=self.browse_file).pack(pady=5)

        button_frame = ttk.Frame(frame)
        button_frame.pack(pady=20)
        ttk.Button(button_frame, text="Chiffrer", command=self.encrypt_file).grid(row=0, column=0, padx=10)
        ttk.Button(button_frame, text="Déchiffrer", command=self.decrypt_file).grid(row=0, column=1, padx=10)

    def browse_file(self):
        """Permet de sélectionner un fichier."""
        file_path = filedialog.askopenfilename()
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, file_path)

    def encrypt_file(self):
        """Chiffre le fichier."""
        self.process_file(encrypt=True)

    def decrypt_file(self):
        """Déchiffre le fichier."""
        self.process_file(encrypt=False)

    def process_file(self, encrypt):
        """Traite le fichier pour le chiffrer ou le déchiffrer."""
        key = self.key_entry.get()
        file_path = self.file_entry.get()

        if not key or not file_path:
            messagebox.showerror("Erreur", "Veuillez remplir tous les champs.")
            return

        try:
            # Génération de la clé AES
            key = sha256(key.encode()).digest()

            with open(file_path, "rb") as f:
                data = f.read()

            cipher = AES.new(key, AES.MODE_CBC, iv=b"0123456789abcdef")
            if encrypt:
                processed_data = cipher.encrypt(pad(data, AES.block_size))
                output_path = file_path + ".enc"
            else:
                processed_data = unpad(cipher.decrypt(data), AES.block_size)
                output_path = file_path.replace(".enc", "")

            with open(output_path, "wb") as f:
                f.write(processed_data)

            messagebox.showinfo("Succès", f"Fichier {'chiffré' if encrypt else 'déchiffré'} : {output_path}")

        except Exception as e:
            messagebox.showerror("Erreur", f"Une erreur est survenue : {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = NyxApp(root)
    root.mainloop()
