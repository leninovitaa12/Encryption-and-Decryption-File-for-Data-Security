# Import library yang dibutuhkan
import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import os
import random

# Fungsi membuat kunci AES acak (default 16 byte / AES-128)
def generate_trng_key(size=16):
    return get_random_bytes(size)

# Fungsi Caesar Cipher untuk data bytes
def caesar_cipher_bytes(data, shift, encrypt=True):
    shift = shift if encrypt else -shift
    return bytes((byte + shift) % 256 for byte in data)

# Fungsi ENKRIPSI file otomatis
def encrypt_file_auto(file_path):
    shift = random.randint(1, 9)  # Shift Caesar acak
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # Enkripsi Caesar
    caesar_encrypted = caesar_cipher_bytes(plaintext, shift, encrypt=True)

    # Enkripsi AES (EAX mode)
    aes_key = generate_trng_key()
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(caesar_encrypted)

    # Buat pasangan kunci RSA
    rsa_key = RSA.generate(2048)
    private_key = rsa_key.export_key()
    public_key = rsa_key.publickey().export_key()

    # Simpan kunci RSA ke file
    output_folder = os.path.dirname(os.path.abspath(__file__))
    private_key_path = os.path.join(output_folder, "private.pem")
    public_key_path = os.path.join(output_folder, "public.pem")

    with open(private_key_path, "wb") as f:
        f.write(private_key)
    with open(public_key_path, "wb") as f:
        f.write(public_key)

    # Enkripsi kunci AES menggunakan RSA
    cipher_rsa = PKCS1_OAEP.new(rsa_key.publickey())
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # Simpan nama file asli
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
def decrypt_file_auto(file_path):
    output_folder = os.path.dirname(os.path.abspath(__file__))
    private_key_path = os.path.join(output_folder, "private.pem")

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
        shift = ciphertext[-1]
        ciphertext = ciphertext[:-1]

    aes_key = cipher_rsa.decrypt(encrypted_aes_key)
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

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
root = tk.Tk()
root.title("Enkripsi & Dekripsi File Otomatis")

frame = tk.Frame(root, padx=150, pady=70)
frame.pack(pady=20)

tk.Button(frame, text="Enkripsi File", command=lambda: encrypt_file_auto(open_file())).pack(pady=5)
tk.Button(frame, text="Dekripsi File", command=lambda: decrypt_file_auto(open_file())).pack(pady=5)
tk.Button(frame, text="Keluar", command=root.quit).pack(pady=5)

root.mainloop()
