import json, base64
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256

# helper functions
def b64(x): return base64.b64encode(x).decode('utf-8')
def ub64(s): return base64.b64decode(s.encode('utf-8'))

def decrypt_package(package_json, recipient_priv_pem, sender_pub_pem, out_file):
    # 1. Load package
    with open(package_json, 'r') as f:
        package = json.load(f)

    enc_aes_key = ub64(package['enc_aes_key'])
    nonce = ub64(package['nonce'])
    tag = ub64(package['tag'])
    ciphertext = ub64(package['ciphertext'])
    signature = ub64(package['signature'])

    # 2. Verify signature
    sender_pub = RSA.import_key(open(sender_pub_pem, 'rb').read())
    h = SHA256.new(ciphertext + nonce + tag)
    verifier = pss.new(sender_pub)
    try:
        verifier.verify(h, signature)
        print("Signature verified ✅")
    except (ValueError, TypeError):
        print("Signature verification failed ❌")
        return

    # 3. Decrypt AES key
    recipient_priv = RSA.import_key(open(recipient_priv_pem, 'rb').read())
    rsa_cipher = PKCS1_OAEP.new(recipient_priv)
    aes_key = rsa_cipher.decrypt(enc_aes_key)

    # 4. Decrypt file content
    aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = aes.decrypt_and_verify(ciphertext, tag)

    # 5. Save decrypted file
    with open(out_file, 'wb') as f:
        f.write(plaintext)
    print(f"Decrypted file saved as {out_file}")

# Run example
if __name__ == '__main__':
    decrypt_package(
        package_json='../sender/package.json',      # encrypted package
        recipient_priv_pem='../keys/recipient_priv.pem',
        sender_pub_pem='../keys/sender_pub.pem',
        out_file='sample_decrypted.txt'            # recovered original file
    )
