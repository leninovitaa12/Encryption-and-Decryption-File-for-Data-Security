import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import os

# Fungsi membuat kunci AES dari password
def generate_aes_key_from_password(password):
    hashed = SHA256.new(password.encode('utf-8')).digest()
    return hashed[:16]  # Gunakan 16 byte untuk AES-128

# Fungsi Caesar Cipher untuk data bytes
def caesar_cipher_bytes(data, shift, encrypt=True):
    shift = shift if encrypt else -shift
    return bytes((byte + shift) % 256 for byte in data)

# Fungsi menghitung shift dari password (0-9)
def get_shift_from_password(password):
    return sum(bytearray(password.encode('utf-8'))) % 10 + 1

# Fungsi ENKRIPSI file otomatis
def encrypt_file_auto(file_path, password):
    shift = get_shift_from_password(password)
    aes_key = generate_aes_key_from_password(password)

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Enkripsi Caesar
    caesar_encrypted = caesar_cipher_bytes(plaintext, shift, encrypt=True)

    # Enkripsi AES
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(caesar_encrypted)

    # Buat pasangan kunci RSA
    rsa_key = RSA.generate(2048)
    private_key = rsa_key.export_key()
    public_key = rsa_key.publickey().export_key()

    output_folder = os.path.dirname(os.path.abspath(__file__))
    with open(os.path.join(output_folder, "private.pem"), "wb") as f:
        f.write(private_key)
    with open(os.path.join(output_folder, "public.pem"), "wb") as f:
        f.write(public_key)

    cipher_rsa = PKCS1_OAEP.new(rsa_key.publickey())
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # Simpan file terenkripsi
    original_filename = os.path.basename(file_path)
    encrypted_file_path = file_path + ".encrypted"

    with open(encrypted_file_path, 'wb') as f:
        f.write(len(original_filename).to_bytes(2, 'big'))
        f.write(original_filename.encode('utf-8'))
        f.write(encrypted_aes_key)
        f.write(cipher_aes.nonce)
        f.write(tag)
        f.write(ciphertext)
        f.write(bytes([shift]))

    messagebox.showinfo("Sukses", f"File berhasil dienkripsi!\nOutput: {encrypted_file_path}")

# Fungsi DEKRIPSI file otomatis
def decrypt_file_auto(file_path, password):
    shift = get_shift_from_password(password)
    aes_key = generate_aes_key_from_password(password)

    private_key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "private.pem")
    if not os.path.exists(private_key_path):
        messagebox.showerror("Error", "Kunci privat RSA tidak ditemukan!")
        return

    with open(private_key_path, 'rb') as f:
        private_key = RSA.import_key(f.read())

    cipher_rsa = PKCS1_OAEP.new(private_key)

    with open(file_path, 'rb') as f:
        filename_len = int.from_bytes(f.read(2), 'big')
        original_filename = f.read(filename_len).decode('utf-8')
        encrypted_aes_key = f.read(256)
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read(-1)
        stored_shift = ciphertext[-1]
        ciphertext = ciphertext[:-1]

    try:
        decrypted_aes_key = cipher_rsa.decrypt(encrypted_aes_key)
        if decrypted_aes_key != aes_key:
            raise ValueError("Kunci AES tidak cocok")
    except:
        messagebox.showerror("Error", "Password salah atau file rusak!")
        return

    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    try:
        decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    except:
        messagebox.showerror("Error", "Verifikasi tag gagal. Password salah?")
        return

    final_plaintext = caesar_cipher_bytes(decrypted_data, shift, encrypt=False)

    decrypted_file_path = os.path.join(
        os.path.dirname(file_path),
        f"{os.path.splitext(original_filename)[0]}_decrypted{os.path.splitext(original_filename)[1]}"
    )

    with open(decrypted_file_path, 'wb') as f:
        f.write(final_plaintext)

    messagebox.showinfo("Sukses", f"File berhasil didekripsi!\nOutput: {decrypted_file_path}")

# Fungsi pilih file
def open_file():
    return filedialog.askopenfilename()

# GUI
def ask_and_encrypt():
    file = open_file()
    if file:
        password = simpledialog.askstring("Password", "Masukkan password enkripsi:")
        if password:
            encrypt_file_auto(file, password)

def ask_and_decrypt():
    file = open_file()
    if file:
        password = simpledialog.askstring("Password", "Masukkan password dekripsi:")
        if password:
            decrypt_file_auto(file, password)

root = tk.Tk()
root.title("Enkripsi & Dekripsi File Otomatis dengan Password")

frame = tk.Frame(root, padx=150, pady=70)
frame.pack(pady=20)

tk.Button(frame, text="Enkripsi File", command=ask_and_encrypt).pack(pady=5)
tk.Button(frame, text="Dekripsi File", command=ask_and_decrypt).pack(pady=5)
tk.Button(frame, text="Keluar", command=root.quit).pack(pady=5)

root.mainloop()