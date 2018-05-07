import os, sys
import base64
from datetime import datetime
from Config import Config
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, padding, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class Crypto:
    publicKey = None
    fingerprint = None
    privateKey = None

    @staticmethod
    def generateKeyPair():  # TODO: Save new keypair to config file to retrieve on reboot
        key = rsa.generate_private_key(public_exponent=65537,
                                       key_size=2048,
                                       backend=default_backend()
                                       )
        f = open('private.pem', 'w')
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()))
        f.close()
        f = open('public.pem', 'w')
        f.write(key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))
        f.close()

        return key

    @staticmethod
    def encrypt(plain_text):
        backend = default_backend()
        AESkey = os.urandom(16)
        AESiv = os.urandom(16)

        HMACkey = os.urandom(20)

        # Generate Content

        # prepend datetime
        plain_text = datetime.utcnow().strftime('%y%m%d%H%M%S') + plain_text
        # padding
        padder = padding.PKCS7(128).padder()
        padded_text = padder.update(plain_text)
        padded_text += padder.finalize()
        # encrypt
        cipher = Cipher(algorithms.AES(AESkey), modes.CBC(AESiv), backend=backend)
        encryptor = cipher.encryptor()
        encrypted_message = encryptor.update(padded_text) + encryptor.finalize()
        # prepend IV
        content = AESiv + encrypted_message

        # Generate HMAC
        h = hmac.HMAC(HMACkey, hashes.SHA1(), backend=default_backend())
        h.update(content)
        h = h.finalize()

        # Generate Header

        # combine keys used
        keys = HMACkey + AESkey

        # Sign hash
        signed_keys = Crypto.privateKey.sign(
            keys,
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA1()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA1()
        )

        header = 'NESS' + Crypto.fingerprint + signed_keys + keys

        # encrypt header
        # header is too long so we split it encrypt each block and then merge

        # split bytes
        first_half = header[:214]
        second_half = header[214:]

        encrypted_header = Crypto.publicKey.encrypt(
            header,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )

        # build encrypted packet
        return header + hmac + content

    def decrypt(self, encrypted_text):
        pass

    def insertKey(self, key):
        gpg = gnupg.GPG()
        import_result = gpg.import_keys(key)
        return import_result

    def listRecipientFingerprints(self):
        gpg = gnupg.GPG()
        public_keys = gpg.list_keys().key_map
        keys = {}
        for key in public_keys.values():
            s = str(key['uids'])
            email = s[s.find('<') + 1:s.rfind('>')]
            keys[email] = key['fingerprint']
        return keys

    def exportPublicKey(self, key):
        gpg = gnupg.GPG()
        ascii_armored_public_keys = gpg.export_keys(key)
        return ascii_armored_public_keys

    def importPublicKey(self, key):
        gpg = gnupg.GPG()
        result = gpg.import_keys(key)
        # pprint(result.results)

    @staticmethod
    def loadKeys():
        with open("public.pem", "rb") as key_file:
            Crypto.publicKey = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        with open("private.pem", "rb") as key_file:
            Crypto.privateKey = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
        # Hash SHA-1
        digest = hashes.Hash(hashes.SHA1(), backend=default_backend())
        digest.update(Crypto.publicKey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))
        Crypto.fingerprint = digest.finalize()


if __name__ == "__main__":
    Crypto.loadKeys()
    x = Crypto.encrypt('hello secret')
    print x
