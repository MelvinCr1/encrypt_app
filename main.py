import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import time

# Fonction pour dériver une clé à partir d'un mot de passe
def derive_key_from_password(password: str, salt: bytes, key_length=32, algorithm='Fernet') -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Initialisation de l'interface et variables globales
theme_mode = "light"  # Mode par défaut (clair)
failed_attempts = 0  # Nombre de tentatives ratées
MAX_ATTEMPTS = 3  # Nombre maximum de tentatives échouées
LOCK_TIME = 10  # Temps initial de blocage (en secondes)
supported_formats = [("Documents Word", "*.docx"), ("Feuilles Excel", "*.xlsx"),
                     ("Images", "*.jpg;*.jpeg;*.png"), ("Vidéos", "*.mp4"),
                     ("Documents PDF", "*.pdf"), ("Tous les fichiers", "*.*")]

# Basculer le mode sombre/clair
def toggle_theme():
    global theme_mode
    if theme_mode == "light":
        app.configure(bg="#2E2E2E")
        history_label.configure(bg="#2E2E2E", fg="white")
        history_box.configure(bg="#363636", fg="white")
        theme_mode = "dark"
    else:
        app.configure(bg="#f5f5f5")
        history_label.configure(bg="#f5f5f5", fg="black")
        history_box.configure(bg="white", fg="black")
        theme_mode = "light"

# Ajouter des messages dans l'historique
def add_to_history(message: str):
    history_box.insert(tk.END, message + "\n")
    history_box.see(tk.END)  # Défiler automatiquement jusqu'à la fin

# Validation des mots de passe faibles
def validate_password(password: str):
    if len(password) < 8:
        raise ValueError("Le mot de passe doit contenir au moins 8 caractères.")
    if password.isnumeric() or password.isalpha() or password.isalnum():
        raise ValueError("Le mot de passe doit inclure des chiffres, des lettres et des caractères spéciaux.")

# Blocage exponentiel en cas de brute force
def brute_force_protection():
    global failed_attempts, LOCK_TIME
    if failed_attempts >= MAX_ATTEMPTS:
        messagebox.showwarning("Blocage temporaire", f"Vous avez atteint le nombre maximum de tentatives. Attendez {LOCK_TIME} secondes avant de réessayer.")
        time.sleep(LOCK_TIME)
        LOCK_TIME *= 2  # Double le temps de blocage
        failed_attempts = 0  # Réinitialiser le compteur

# Gestion sûre des ouvertures de fichiers
def safe_open_file(file_path, mode):
    try:
        return open(file_path, mode)
    except Exception as e:
        raise IOError(f"Erreur lors de l'ouverture du fichier {file_path} : {str(e)}")

# Fonction pour crypter un ou plusieurs fichiers
def encrypt_multiple_files():
    file_paths = filedialog.askopenfilenames(title="Sélectionnez les fichiers à chiffrer", filetypes=supported_formats)
    if not file_paths:
        return

    def on_password_submit():
        password = password_entry.get()
        algorithm = algorithm_var.get()
        save_original = save_original_var.get()
        password_window.destroy()

        try:
            validate_password(password)
        except ValueError as e:
            messagebox.showerror("Erreur", f"Mot de passe invalide : {str(e)}")
            return

        # Chiffrement des fichiers
        success_count = 0
        for file_path in file_paths:
            salt = os.urandom(16)
            try:
                # Utilise l'algorithme sélectionné
                key = derive_key_from_password(password, salt, algorithm=algorithm)
                with safe_open_file(file_path, "rb") as file:
                    data = file.read()

                if algorithm == "Fernet":
                    fernet = Fernet(key)
                    encrypted_data = fernet.encrypt(data)
                elif algorithm == "AES256":
                    cipher = Cipher(algorithms.AES(key[:32]), modes.GCM(os.urandom(12)), backend=default_backend())
                    encryptor = cipher.encryptor()
                    encrypted_data = encryptor.update(data) + encryptor.finalize()
                else:
                    raise ValueError("Algorithme non pris en charge.")

                encrypted_file_path = file_path
                if save_original:
                    base_name = os.path.basename(file_path)
                    encrypted_file_path = os.path.join(os.path.dirname(file_path), f"encrypted_{base_name}")

                with safe_open_file(encrypted_file_path, "wb") as file:
                    file.write(salt + encrypted_data)

                add_to_history(f"Fichier chiffré : {encrypted_file_path}")
                success_count += 1

            except Exception as e:
                add_to_history(f"Erreur lors du chiffrement : {file_path} ({str(e)})")

        # Résultats
        if success_count == len(file_paths):
            messagebox.showinfo("Succès", f"Tous les fichiers ({success_count}) ont été chiffrés avec succès.")
        else:
            messagebox.showwarning("Partiellement réussi", f"{success_count} fichier(s) sur {len(file_paths)} ont été chiffrés.")

    # Fenêtre pour mot de passe et algorithme
    password_window = tk.Toplevel()
    password_window.title("Mot de passe et Algorithme")
    password_window.geometry("350x250")
    password_window.configure(bg="#f5f5f5")

    label = tk.Label(password_window, text="Entrez un mot de passe :", font=("Arial", 12), bg="#f5f5f5", fg="black")
    label.pack(pady=10)

    password_entry = tk.Entry(password_window, show="*", font=("Arial", 12))
    password_entry.pack(pady=5)

    save_original_var = tk.BooleanVar(value=False)
    save_original_check = tk.Checkbutton(
        password_window, text="Conserver les fichiers originaux",
        variable=save_original_var, font=("Arial", 10), bg="#f5f5f5", fg="black"
    )
    save_original_check.pack(pady=5)

    algo_label = tk.Label(password_window, text="Sélectionnez l'algorithme :", font=("Arial", 12), bg="#f5f5f5", fg="black")
    algo_label.pack(pady=10)

    algorithm_var = tk.StringVar()
    algorithm_dropdown = tk.OptionMenu(password_window, algorithm_var, "Fernet", "AES256")
    algorithm_var.set("Fernet")  # Algorithme par défaut
    algorithm_dropdown.pack()

    submit_button = tk.Button(password_window, text="Valider", font=("Arial", 12), bg="#4CAF50", fg="white",
                               relief="flat", command=on_password_submit)
    submit_button.pack(pady=10, ipadx=10, ipady=5)

# Fonction pour déchiffrer un fichier
def decrypt_file():
    global failed_attempts
    brute_force_protection()  # Protection brute force
    file_path = filedialog.askopenfilename(title="Sélectionnez le fichier à déchiffrer", filetypes=supported_formats)
    if not file_path:
        return

    def on_password_submit():
        global failed_attempts
        password = password_entry.get()
        password_window.destroy()

        try:
            salt = b''
            with safe_open_file(file_path, "rb") as file:
                salt, encrypted_data = file.read(16), file.read()

            key = derive_key_from_password(password, salt)
            fernet = Fernet(key)

            decrypted_data = fernet.decrypt(encrypted_data)

            decrypted_file_path = file_path.replace("encrypted_", "")
            with safe_open_file(decrypted_file_path, "wb") as file:
                file.write(decrypted_data)

            add_to_history(f"Fichier déchiffré : {decrypted_file_path}")
            failed_attempts = 0  # Réinitialise après succès
            messagebox.showinfo("Succès", f"Le fichier '{file_path}' a été déchiffré avec succès.")
        except Exception as e:
            failed_attempts += 1
            add_to_history(f"Erreur lors du déchiffrement : {file_path} ({str(e)})")
            messagebox.showerror("Erreur", f"Impossible de déchiffrer le fichier. Mot de passe incorrect ou fichier corrompu.")

    # Fenêtre pour saisir le mot de passe
    password_window = tk.Toplevel()
    password_window.title("Mot de passe")
    password_window.geometry("300x200")
    password_window.configure(bg="#f5f5f5")

    label = tk.Label(password_window, text="Entrez un mot de passe :", font=("Arial", 12), bg="#f5f5f5", fg="black")
    label.pack(pady=10)

    password_entry = tk.Entry(password_window, show="*", font=("Arial", 12))
    password_entry.pack(pady=5)

    submit_button = tk.Button(password_window, text="Valider", font=("Arial", 12), bg="#4CAF50", fg="white",
                               relief="flat", command=on_password_submit)
    submit_button.pack(pady=10, ipadx=10, ipady=5)

# Interface principale
app = tk.Tk()
app.title("Encrypt")
app.geometry("500x500")
app.configure(bg="#f5f5f5")

encrypt_button = tk.Button(app, text="Chiffrer des fichiers", font=("Arial", 12), bg="#2196F3", fg="white", relief="flat",
                           command=encrypt_multiple_files)
encrypt_button.pack(pady=10, ipadx=10, ipady=5)

decrypt_button = tk.Button(app, text="Déchiffrer un fichier", font=("Arial", 12), bg="#FF5722", fg="white", relief="flat",
                           command=decrypt_file)
decrypt_button.pack(pady=10, ipadx=10, ipady=5)

history_label = tk.Label(app, text="Historique des opérations :", font=("Arial", 12, "bold"), bg="#f5f5f5", fg="black")
history_label.pack(pady=10)

history_box = tk.Text(app, height=10, width=60, bg="white", fg="black", font=("Arial", 10))
history_box.pack(pady=5)

theme_button = tk.Button(app, text="Basculer Mode Sombre/Clair", font=("Arial", 12), bg="#808080", fg="white",
                         relief="flat", command=toggle_theme)
theme_button.pack(pady=20, ipadx=10, ipady=5)

app.mainloop()