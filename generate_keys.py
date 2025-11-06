from Crypto.PublicKey import RSA

def gen_rsa_pair(bits=2048, priv_path='priv.pem', pub_path='pub.pem'):
    key = RSA.generate(bits)
    with open(priv_path, 'wb') as f:
        f.write(key.export_key('PEM'))
    with open(pub_path, 'wb') as f:
        f.write(key.publickey().export_key('PEM'))
    print("Saved:", priv_path, pub_path)

if __name__ == '__main__':
    # Generate sender key pair
    gen_rsa_pair(2048, 'keys/sender_priv.pem', 'keys/sender_pub.pem')
    # Generate recipient key pair
    gen_rsa_pair(2048, 'keys/recipient_priv.pem', 'keys/recipient_pub.pem')
