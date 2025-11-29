import os
import getpass
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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

def descriptografar(arquivo, senha):
    if not os.path.isfile(arquivo):
        print("Arquivo não encontrado:", arquivo)
        return

    with open(arquivo, "rb") as f:
        cab = f.read(len(MAGIC))
        if cab != MAGIC:
            print("Arquivo inválido.")
            return

        salt = f.read(SALT_SIZE)
        nonce = f.read(NONCE_SIZE)
        cifrado = f.read()

    chave = gerar_chave(senha, salt)
    aes = AESGCM(chave)
    dados = aes.decrypt(nonce, cifrado, None)

    saida = arquivo.replace(".enc", ".dec")
    with open(saida, "wb") as f:
        f.write(dados)

    print("Arquivo descriptografado:", saida)


if __name__ == "__main__":
    nome = input("Arquivo .enc: ")
    senha = getpass.getpass("Senha: ").encode()
    descriptografar(nome, senha)
