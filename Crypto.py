import os, sys
from datetime import datetime
from Config import Config
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, padding, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


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
        AESkey = os.urandom(16)
        AESiv = os.urandom(16)

        HMACkey = os.urandom(20)

        # Generate Content

        # prepend datetime
        plain_text = datetime.utcnow().strftime('%y%m%d%H%M%SZ') + plain_text
        # padding
        padder = padding.PKCS7(128).padder()
        padded_text = padder.update(plain_text)
        padded_text += padder.finalize()
        # encrypt
        encryptor = Cipher(algorithms.AES(AESkey), modes.CBC(AESiv), backend=default_backend()).encryptor()
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

        header = b'NESS' + Crypto.fingerprint + signed_keys + keys

        # encrypt header
        # header is too long so we split it encrypt each block and then merge

        # split bytes
        first_half = header[:158]
        second_half = header[158:]

        # the key used should be the recipient's public key, however
        # for testing purposes we will use our own key so that we can decrypt and test this module
        encrypted_header_1 = Crypto.publicKey.encrypt(
            first_half,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        encrypted_header_2 = Crypto.publicKey.encrypt(
            second_half,
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        # build full packet
        full_packet = encrypted_header_1 + encrypted_header_2 + h + content
        return full_packet


    @staticmethod
    def decrypt(encrypted_message):
        # The header is two blocks 256-byte long but we only need the first block to verify the 'NESS' flag
        encrypted_first_half = encrypted_message[:256]
        try:
            first_half_header = Crypto.privateKey.decrypt(
                encrypted_first_half,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None
                )
            )

            if first_half_header[:4] == 'NESS':
                print 'Packet opened'
            else:
                raise ValueError('Nessuno flag not found')

            # Decrypt second half of the header
            encrypted_second_half = encrypted_message[256:512]
            second_half_header = Crypto.privateKey.decrypt(
                encrypted_second_half,
                asymmetric_padding.OAEP(
                    mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA1()),
                    algorithm=hashes.SHA1(),
                    label=None
                )
            )
            header = first_half_header + second_half_header
            # now we retrieve the HMAC key and AES key and we verify the signed hash
            # hmac key is 20 bytes
            hmac_key = header[-36:-16]

            # aes key is 16 bytes
            aes_key = header[-16:]

            # get the signature [256 bytes]
            signature = header[24:280]

            # verify signature on keys
            keys = hmac_key + aes_key

            Crypto.publicKey.verify(
                signature,
                keys,
                asymmetric_padding.PSS(
                    mgf=asymmetric_padding.MGF1(hashes.SHA1()),
                    salt_length=asymmetric_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA1()
            )
            print 'Signature is valid'

            # get the content block which is after the padded header[512 bytes] and HMAC[20 bytes]
            content_block = encrypted_message[532:]
            iv = content_block[:16]
            message = content_block[16:]
            # use the aes key with the IV to decrypt the message
            decryptor = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend()).decryptor()

            paddedText = decryptor.update(message) + decryptor.finalize()

            # finally we remove the padding
            unpadder = padding.PKCS7(128).unpadder()
            plain_text = unpadder.update(paddedText) + unpadder.finalize()
            return plain_text

        except InvalidSignature:
            print "Packet is invalid"
            # should not forward
            raise Exception('Invalid packet')

        except ValueError:
            print 'Decryption failed, forwarding...'
            # call method to forward the packet
            return False

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

# TEST CRYPTOGRAPHY
if __name__ == "__main__":
    # load keys
    Crypto.loadKeys()
    # encrypt 'hello secret'
    encrypted = Crypto.encrypt(b'hello secret')
    print 'Encrypted message:\n' + encrypted
    # decrypt message
    decrypted = Crypto.decrypt(encrypted)
    if decrypted:
        # strip off the time
        time = decrypted[:13]
        time = datetime.strptime(time, '%y%m%d%H%M%SZ').strftime('%d/%b/%y %H:%M:%S')
        text = decrypted[13:]
        print 'Message\n' + time + ': ' + text
