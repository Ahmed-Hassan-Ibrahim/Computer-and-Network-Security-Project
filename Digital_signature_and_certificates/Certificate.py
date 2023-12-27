from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    return private_key, public_key

def generate_self_signed_certificate(private_key, public_key, subject_name, issuer_name):
    builder = x509.CertificateBuilder()

    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'California'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u'San Francisco'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'My Organization'),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_name),
    ]))

    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'California'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u'San Francisco'),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'My Organization'),
        x509.NameAttribute(NameOID.COMMON_NAME, issuer_name),
    ]))

    builder = builder.not_valid_before(datetime.datetime.utcnow())
    builder = builder.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))

    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(public_key)

    certificate = builder.sign(
        private_key,
        hashes.SHA256(),
        default_backend()
    )

    return certificate

def save_private_key(private_key, filename):
    with open(filename, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

def save_public_key(public_key, filename):
    with open(filename, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def save_certificate(certificate, filename):
    with open(filename, 'wb') as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

if __name__ == "__main__":
    import datetime
    from cryptography.hazmat.primitives import hashes

    subject_name = "sis.com"
    issuer_name = "authority.com"

    private_key, public_key = generate_key_pair()
    certificate = generate_self_signed_certificate(private_key, public_key, subject_name, issuer_name)

    save_private_key(private_key, "private_key.pem")
    save_public_key(public_key, "public_key.pem")
    save_certificate(certificate, "certificate.pem")
