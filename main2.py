import os
import sys
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Key and IV (Initialization Vector)
key = b'1234567890123456'
iv = b'1234567890123456'

def encrypt_file(file_path):
    # Read file content
    with open(file_path, 'rb') as file:
        content = file.read()
    # Encrypt content
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    encrypted_content = encryptor.encrypt(pad(content, AES.block_size))

    new_filename = base64.b64encode((os.path.basename(file_path)).encode())
    new_filename = new_filename.decode()

    new_filepath = str(os.path.dirname(file_path)) + "\\" + new_filename
    print(type(new_filename))
    # Write encrypted content to file
    with open(new_filepath, 'wb') as file:
        file.write(encrypted_content)
    
    os.remove(file_path)

def decrypt_file(encrypted_file_path):
    # Read encrypted content
    with open(encrypted_file_path, 'rb') as file:
        encrypted_content = file.read()
    # Decrypt content
    decryptor = AES.new(key, AES.MODE_CBC, iv)
    decrypted_content = unpad(decryptor.decrypt(encrypted_content), AES.block_size)
    # Write decrypted content to file

    encrypted_file_path1 = base64.b64decode((os.path.basename(encrypted_file_path)).encode())
    encrypted_file_path1 = encrypted_file_path1.decode()

    new_filepath = str(os.path.dirname(encrypted_file_path)) + "\\" + encrypted_file_path1

    with open(new_filepath, 'wb') as file:  # Remove '.enc' extension
        file.write(decrypted_content)
    
    os.remove(encrypted_file_path)

def main():
    if len(sys.argv) != 3 or sys.argv[2] not in ['enc', 'dec']:
        print("Usage: python main.py <key> <enc/dec>")
        sys.exit(1)

    mode = sys.argv[2]

    script_name = os.path.basename(__file__)

    if mode == 'enc':
        for root, _, files in os.walk('.'):
            for file in files:
                if file != script_name:
                    file_path = os.path.join(root, file)
                    encrypt_file(file_path)
    elif mode == 'dec':
        for root, _, files in os.walk('.'):
            for file in files:
                if file != script_name:
                    file_path = os.path.join(root, file)
                    decrypt_file(file_path)

if __name__ == "__main__":
    main()
