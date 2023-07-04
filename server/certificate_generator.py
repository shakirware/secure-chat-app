from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

def generate_private_key(file_path):
    """
    Generates a private key and saves it to the specified file path.

    Args:
        file_path (str): The path where the private key will be saved.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(file_path, 'wb') as f:
        f.write(pem)

def generate_csr(file_path, private_key_path, common_name):
    """
    Generates a Certificate Signing Request (CSR) using the private key.

    Args:
        file_path (str): The path where the CSR will be saved.
        private_key_path (str): The path to the private key file.
        common_name (str): The common name (CN) for the CSR.
    """
    with open(private_key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .sign(private_key, hashes.SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM)
    with open(file_path, 'wb') as f:
        f.write(csr_pem)

def generate_certificate(file_path, private_key_path, csr_path):
    """
    Generates a self-signed certificate using the private key and CSR.

    Args:
        file_path (str): The path where the certificate will be saved.
        private_key_path (str): The path to the private key file.
        csr_path (str): The path to the CSR file.
    """
    with open(private_key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    with open(csr_path, 'rb') as f:
        csr = x509.load_pem_x509_csr(f.read())
    certificate = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(csr.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
    with open(file_path, 'wb') as f:
        f.write(certificate_pem)

def generate_server_certificates(private_key_path, certificate_path, common_name='localhost', csr_path='./server/certs/server.csr'):
    """
    Generates a self-signed certificate using the provided private key path, CSR path,
    and certificate path. The common name (CN) is optional and defaults to 'localhost'.

    Args:
        private_key_path (str): The path to the private key file.
        csr_path (str): The path to the CSR file.
        certificate_path (str): The path where the certificate will be saved.
        common_name (str, optional): The common name (CN) for the certificate.
            Defaults to 'localhost'.
    """
    generate_private_key(private_key_path)
    generate_csr(csr_path, private_key_path, common_name)
    generate_certificate(certificate_path, private_key_path, csr_path)
