from cryptography.hazmat.primitives import padding
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class CustomCipher16:
    def __init__(self, key):
        self.key = bytes.fromhex(key)
    
    def encrypt(self, plaintext, mode):
        plaintext = plaintext.encode()
        iv_or_nonce = os.urandom(16)
        
        # Padding untuk ECB dan CBC
        if mode in ['ECB', 'CBC']:
            padder = padding.PKCS7(128).padder()
            plaintext = padder.update(plaintext) + padder.finalize()
        
        cipher = self._get_cipher(mode, iv_or_nonce)
        encryptor = cipher.encryptor()
        ciphertext = iv_or_nonce + encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext.hex()
    
    def decrypt(self, ciphertext, mode):
        ciphertext = bytes.fromhex(ciphertext)
        iv_or_nonce = ciphertext[:16]
        ciphertext = ciphertext[16:]
        
        cipher = self._get_cipher(mode, iv_or_nonce)
        decryptor = cipher.decryptor()
        decrypted_text = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpadding untuk ECB dan CBC
        if mode in ['ECB', 'CBC']:
            unpadder = padding.PKCS7(128).unpadder()
            decrypted_text = unpadder.update(decrypted_text) + unpadder.finalize()
        
        return decrypted_text.decode()
    
    def _get_cipher(self, mode, iv_or_nonce):
        if mode == 'ECB':
            return Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        elif mode == 'CBC':
            return Cipher(algorithms.AES(self.key), modes.CBC(iv_or_nonce), backend=default_backend())
        elif mode == 'CFB':
            return Cipher(algorithms.AES(self.key), modes.CFB(iv_or_nonce), backend=default_backend())
        elif mode == 'OFB':
            return Cipher(algorithms.AES(self.key), modes.OFB(iv_or_nonce), backend=default_backend())
        elif mode == 'CTR':
            return Cipher(algorithms.AES(self.key), modes.CTR(iv_or_nonce), backend=default_backend())
        else:
            raise ValueError("Unsupported mode")
