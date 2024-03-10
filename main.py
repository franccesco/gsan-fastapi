from fastapi import FastAPI
import ssl
import socket
from os import environ

from fastapi import HTTPException, Depends, status, Header
from OpenSSL import crypto
from pyasn1.codec.der import decoder
from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful
from fastapi.security import APIKeyHeader


class DNSName(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "ia5String", char.IA5String().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
        )
    )


class IPAddress(univ.OctetString):
    pass


class GeneralName(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType(
            "dNSName", char.IA5String().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
        ),
        namedtype.NamedType(
            "iPAddress", IPAddress().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))
        ),
    )


class GeneralNames(univ.SequenceOf):
    componentType = GeneralName()


app = FastAPI()

api_key_header = APIKeyHeader(name="X-API-Key")


def get_api_key(api_key: str = Depends(api_key_header)):
    """
    Validates the API key provided in the request header.

    Args:
        api_key (str): The API key extracted from the request header.

    Returns:
        str: The validated API key.

    Raises:
        HTTPException: If the API key is invalid or missing.
    """
    if api_key is None or api_key != environ.get("API_KEY"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
    return api_key


def allow_unsigned_certificate():
    """
    Creates and returns an SSL context that allows the use of unsigned certificates.

    Returns:
        ssl.SSLContext: An SSL context with the hostname verification disabled and certificate verification set to none.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def clean_domains(domains, seen_domains=None) -> tuple:
    """
    Clean a list of domains by removing duplicates and common prefixes.

    Args:
        domains (list): A list of domain names.
        seen_domains (set, optional): A set of previously seen domain names. Defaults to None.

    Returns:
        tuple: A tuple containing a list of cleaned domain names and a set of seen domain names.
    """
    if seen_domains is None:
        seen_domains = set()
    cleaned_domains = set()
    for domain in domains:
        if domain.startswith("*."):
            domain = domain[2:]
        if domain.startswith("www."):
            domain = domain[4:]
        if domain not in seen_domains:
            cleaned_domains.add(domain)
            seen_domains.add(domain)
    return list(cleaned_domains), seen_domains


def get_domains(hostname: str, port: int, seen_domains: set, timeout: int):
    """
    Retrieves the subdomains or IP addresses associated with the SSL certificate.

    Args:
        hostname (str): The hostname to connect to.
        port (int): The port number to connect to.
        seen_domains (set): A set of previously seen domains.

    Returns:
        tuple: A tuple containing two elements:
            - cleaned_domains (list): A list of cleaned subdomains and IP addresses.
            - seen_domains (set): The updated set of seen domains.
    """
    try:
        # Create an SSL context that allows the use of unsigned certificates
        context = allow_unsigned_certificate()

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
                # Retrieve the peer certificate in binary form and load it into an X.509 object
                cert = ssl_sock.getpeercert(binary_form=True)
                x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)

                # Extract the subdomains and IP addresses from the certificate's subjectAltName extension
                # by iterating through the extensions and decoding the subjectAltName extension
                subdomains = []
                for extension_id in range(0, x509.get_extension_count()):
                    ext = x509.get_extension(extension_id)
                    ext_name = ext.get_short_name().decode("utf-8")
                    if ext_name == "subjectAltName":
                        ext_data = ext.get_data()
                        decoded_dat = decoder.decode(ext_data, asn1Spec=GeneralNames())
                        for name in decoded_dat:
                            if isinstance(name, GeneralNames):
                                for entry in range(len(name)):
                                    component = name.getComponentByPosition(entry)
                                    if "dNSName" in component:
                                        # Add the domain name to the list of subdomains
                                        subdomains.append(str(component.getComponent()))
                                    elif "iPAddress" in component:
                                        # Convert the IP address from bytes to a string and add it to the list of subdomains
                                        ip_address = str(ipaddress.ip_address(component.getComponent()))
                                        subdomains.append(ip_address)

                # Clean the subdomains by removing duplicates and common prefixes
                cleaned_domains, seen_domains = clean_domains(subdomains, seen_domains)
                return cleaned_domains, seen_domains
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get("/ssl_domains/{hostname}")
def get_ssl_domains(
    hostname: str, recursive: bool = False, port: int = 443, timeout: int = 5, api_key: str = Depends(get_api_key)
):
    """
    Retrieves SSL domains for a given hostname.

    Args:
        hostname (str): The hostname for which to retrieve SSL domains.
        recursive (bool, optional): Flag indicating whether to recursively retrieve SSL domains for subdomains. Defaults to False.
        port (int, optional): The port number to use for the SSL connection. Defaults to 443.
        api_key (str, optional): The API key to use for authentication. Defaults to Depends(get_api_key).

    Returns:
        dict: A dictionary containing the retrieved SSL domains.
    """
    seen_domains = set()
    domains, seen_domains = get_domains(hostname, port, seen_domains, timeout)
    sub_domains = []
    if recursive:
        for domain in domains:
            if domain != hostname:
                try:
                    new_sub_domains, seen_domains = get_domains(domain, port, seen_domains, timeout)
                    sub_domains.extend(new_sub_domains)
                except HTTPException:
                    continue
    return {"domains": domains + sub_domains}
