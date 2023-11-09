import jks, base64, typer
from cryptography.hazmat.primitives.serialization import pkcs12, Encoding, PrivateFormat, NoEncryption
from cryptography.hazmat.backends import default_backend


def main(pkcs12_file: str, pkcs12_password: str = "", jks_alias: str = "", jks_password: str = "") -> str:
    """
    Main function that loads a PKCS#12 file and converts it into a Java KeyStore (JKS) format, then prints it out.

    Args:
    pkcs12_file (str): The file path to the .p12 or .pfx file to convert.
    pkcs12_password (str, optional): The password for the PKCS#12 file. Defaults to "".
    jks_alias (str, optional): The alias for the JKS store. Defaults to "".
    jks_password (str, optional): The password for the JKS store. Defaults to "".

    Returns:
    str: The base64 encoded Java KeyStore as a string.
    """
    # Extract pk and certs from file.
    pk, certs = load_pkcs12_file(pkcs12_file, pkcs12_password)

    # Use extracted values fo create a jks.
    key_store = create_jks(jks_alias, certs, pk, jks_password)
    print(key_store)

def load_pkcs12_file(file: str, password: str) -> (bytes, list[bytes]):
    """
    Loads a PKCS#12 file and extracts the private key and certificates.

    Args:
    file (str): The file path to the .p12 or .pfx file.
    password (str): The password to decrypt the PKCS#12 file.

    Returns:
    tuple: A tuple containing the serialized private key and a list of serialized certificates.
    """
    with open(file, 'rb') as f:
        pkcs12_data = f.read()
    
    # Load private key and certs.
    pk, cert, additional_certs = pkcs12.load_key_and_certificates(
        pkcs12_data, 
        password.encode() if password else None,
        backend=default_backend()
    )
    
    # Serialize private key to bytes.
    pk_bytes = pk.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())

    # Convert certificates to bytes and put them in a list.
    certs_bytes = [cert.public_bytes(Encoding.DER)]
    if additional_certs:
        for additional_cert in additional_certs:
            certs_bytes.append(additional_cert.public_bytes(Encoding.DER))

    return pk_bytes, certs_bytes

def create_jks(alias: str, certs: list[bytes], pk: bytes, password: str) -> str:
    """
    Creates a Java KeyStore (JKS) from the provided private key and certificates.

    Args:
    alias (str): The alias for the JKS entry.
    certs (list[bytes]): A list of byte strings representing the certificates.
    pk (bytes): The private key in byte string format.
    password (str): The password for the JKS.

    Returns:
    str: The base64 encoded string of the Java KeyStore.
    """
    entry = jks.PrivateKeyEntry.new(
        alias,
        certs,
        pk,
        "rsa_raw"
    )
    key_store = jks.KeyStore.new("jks", [entry]).saves(password)
    return base64.b64encode(key_store).decode()

if __name__ == "__main__":
    typer.run(main)