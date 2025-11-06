import json, base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes

# helper functions
def b64(x): return base64.b64encode(x).decode('utf-8')
def ub64(s): return base64.b64decode(s.encode('utf-8'))

def encrypt_and_package(file_path, recipient_pub_pem, sender_priv_pem, out_json):
    # read file
    with open(file_path, 'rb') as f:
        plaintext = f.read()

    # 1. AES encryption
    aes_key = get_random_bytes(32)  # AES-256
    aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = aes.encrypt_and_digest(plaintext)
    nonce = aes.nonce

    # 2. RSA encrypt AES key
    recipient_key = RSA.import_key(open(recipient_pub_pem, 'rb').read())
    rsa_cipher = PKCS1_OAEP.new(recipient_key)
    enc_aes_key = rsa_cipher.encrypt(aes_key)

    # 3. Sign data
    sender_priv = RSA.import_key(open(sender_priv_pem, 'rb').read())
    h = SHA256.new(ciphertext + nonce + tag)
    signer = pss.new(sender_priv)
    signature = signer.sign(h)

    # 4. Package into JSON
    package = {
        'filename': file_path.split('/')[-1],
        'enc_aes_key': b64(enc_aes_key),
        'nonce': b64(nonce),
        'tag': b64(tag),
        'ciphertext': b64(ciphertext),
        'signature': b64(signature)
    }
    with open(out_json, 'w') as f:
        json.dump(package, f)
    print("Packaged to", out_json)

if __name__ == '__main__':
    file_path = '../sample.txt'
    try:
        encrypt_and_package(
            file_path=file_path,
            recipient_pub_pem='../keys/recipient_pub.pem',
            sender_priv_pem='../keys/sender_priv.pem',
            out_json='package.json'
        )
    except FileNotFoundError:
        print(f"ERROR: File not found: {file_path}")
    except Exception as e:
        print("An error occurred:", e)

