import os
import getpass
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets

MAGIC = b"MYENC"
SALT_SIZE = 16
NONCE_SIZE = 12

def gerar_chave(senha, salt):
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=16384,
        r=8,
        p=1,
    )
    return kdf.derive(senha)

def criptografar(arquivo, senha):
    if not os.path.isfile(arquivo):
        print("Arquivo não encontrado:", arquivo)
        return

    salt = secrets.token_bytes(SALT_SIZE)
    chave = gerar_chave(senha, salt)
    aes = AESGCM(chave)
    nonce = secrets.token_bytes(NONCE_SIZE)

    with open(arquivo, "rb") as f:
        dados = f.read()

    cifrado = aes.encrypt(nonce, dados, None)

    saida = arquivo + ".enc"
    with open(saida, "wb") as f:
        f.write(MAGIC + salt + nonce + cifrado)

    print("Arquivo criptografado:", saida)


if __name__ == "__main__":
    nome = input("Arquivo para criptografar: ")
    senha = getpass.getpass("Senha: ").encode()
    criptografar(nome, senha)
