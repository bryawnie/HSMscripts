import sys

from pkcs11 import lib, ObjectClass
from pkcs11.util.rsa import encode_rsa_public_key
from pkcs11.exceptions import NoSuchToken, PinIncorrect, NoSuchKey
from cryptography.hazmat.primitives.serialization import load_der_public_key, Encoding, PublicFormat
from cryptography.hazmat.backends import default_backend

user_pin = '123456'
key_label = 'MyRSAKey-public'
token_label = 'MyTokencito'
lib_path = '/usr/local/lib/softhsm/libsofthsm2.so'

lib = lib(lib_path)

try:
    token = lib.get_token(token_label=token_label)
except NoSuchToken:
    print('No Token ' + token_label + ' in HSM.')
    sys.exit(1)

try:
    with token.open(user_pin=user_pin) as session:
        try:
            public = session.get_key(
                label=key_label,
                object_class=ObjectClass.PUBLIC_KEY
            )
            der_public_key = encode_rsa_public_key(public)
            public_key_aux = load_der_public_key(der_public_key, backend=default_backend())
            pem = public_key_aux.public_bytes(
                encoding=Encoding.PEM,
                format=PublicFormat.SubjectPublicKeyInfo
            )
            print('Public Key ' + key_label + ' : \n' + str(pem.decode()))
        except NoSuchKey:
            print('No Key ' + key_label + ' in HSM.')
            sys.exit(0)
except PinIncorrect:
    print('Incorrect User Pin.')
    sys.exit(1)