"""
NetSentinel X.509 Certificate Generation Utility
Generates Root CA, Server, and Client Mutual TLS (mTLS) certificates with SAN extensions
using OpenSSL CLI for secure, cryptographically attested microservice communication.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("NetSentinel.CertGen")


def generate_mtls_certificates(certs_dir: str = "certs") -> None:
    """Generate complete PKI hierarchy: Root CA, Server, and Client X.509 certificates."""
    os.makedirs(certs_dir, exist_ok=True)

    ca_key = os.path.join(certs_dir, "ca.key")
    ca_crt = os.path.join(certs_dir, "ca.crt")
    server_key = os.path.join(certs_dir, "server.key")
    server_csr = os.path.join(certs_dir, "server.csr")
    server_crt = os.path.join(certs_dir, "server.crt")
    client_key = os.path.join(certs_dir, "client.key")
    client_csr = os.path.join(certs_dir, "client.csr")
    client_crt = os.path.join(certs_dir, "client.crt")

    server_ext = os.path.join(certs_dir, "server_ext.cnf")
    client_ext = os.path.join(certs_dir, "client_ext.cnf")

    logger.info("Generating NetSentinel Root CA...")
    # 1. Root CA
    subprocess.run([
        "openssl", "req", "-x509", "-new", "-nodes",
        "-keyout", ca_key,
        "-out", ca_crt,
        "-days", "3650",
        "-subj", "/C=US/O=NetSentinel/OU=Security/CN=NetSentinel Root CA"
    ], check=True, capture_output=True)

    # 2. Server Certificate with SAN
    logger.info("Generating NetSentinel Server Certificate & Key with SAN...")
    subprocess.run([
        "openssl", "req", "-new", "-nodes",
        "-keyout", server_key,
        "-out", server_csr,
        "-subj", "/C=US/O=NetSentinel/OU=Gateway/CN=localhost"
    ], check=True, capture_output=True)

    with open(server_ext, "w", encoding="utf-8") as f:
        f.write("basicConstraints=CA:FALSE\n")
        f.write("keyUsage=digitalSignature,keyEncipherment\n")
        f.write("extendedKeyUsage=serverAuth\n")
        f.write("subjectAltName=@alt_names\n\n")
        f.write("[alt_names]\n")
        f.write("DNS.1 = localhost\n")
        f.write("DNS.2 = host.docker.internal\n")
        f.write("IP.1 = 127.0.0.1\n")

    subprocess.run([
        "openssl", "x509", "-req", "-in", server_csr,
        "-CA", ca_crt, "-CAkey", ca_key, "-CAcreateserial",
        "-out", server_crt, "-days", "365",
        "-extfile", server_ext
    ], check=True, capture_output=True)

    # 3. Client Certificate for mTLS Webhook Authentication
    logger.info("Generating NetSentinel Client mTLS Certificate & Key...")
    subprocess.run([
        "openssl", "req", "-new", "-nodes",
        "-keyout", client_key,
        "-out", client_csr,
        "-subj", "/C=US/O=NetSentinel/OU=MitigationEngine/CN=netsentinel-client"
    ], check=True, capture_output=True)

    with open(client_ext, "w", encoding="utf-8") as f:
        f.write("basicConstraints=CA:FALSE\n")
        f.write("keyUsage=digitalSignature,keyEncipherment\n")
        f.write("extendedKeyUsage=clientAuth\n")
        f.write("subjectAltName=@alt_names\n\n")
        f.write("[alt_names]\n")
        f.write("DNS.1 = localhost\n")
        f.write("IP.1 = 127.0.0.1\n")

    subprocess.run([
        "openssl", "x509", "-req", "-in", client_csr,
        "-CA", ca_crt, "-CAkey", ca_key, "-CAcreateserial",
        "-out", client_crt, "-days", "365",
        "-extfile", client_ext
    ], check=True, capture_output=True)

    # Clean up intermediate CSRs and configs
    for tmp in [server_csr, client_csr, server_ext, client_ext]:
        if os.path.exists(tmp):
            os.remove(tmp)

    logger.info("Successfully generated all X.509 mTLS certificates:")
    logger.info(f" - CA Cert:     {ca_crt}")
    logger.info(f" - Server Cert: {server_crt} (Key: {server_key})")
    logger.info(f" - Client Cert: {client_crt} (Key: {client_key})")


if __name__ == "__main__":
    generate_mtls_certificates()
