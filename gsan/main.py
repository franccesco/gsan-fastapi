from fastapi import FastAPI
import ssl
import socket

from concurrent.futures import ThreadPoolExecutor
from fastapi import HTTPException, Depends, status, Header
from pydantic import BaseModel
from OpenSSL import crypto
from pyasn1.codec.der import decoder
from pyasn1.type import univ, char, namedtype, namedval, tag, constraint, useful
from fastapi.security import APIKeyHeader
from typing import List, Set
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.requests import Request
import ipaddress


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


class Parameters(BaseModel):
    """
    Pydantic model for the list of hostnames. Used in the POST request for bulk SSL domain retrieval.

    A list of hostnames is expected in the request body: {"hostnames": ["example.com:port", "sub.example.com"]}.
    """

    hostnames: List[str]
    ssl_port: int = 443
    timeout: int = 5


limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


def allow_unsigned_certificate() -> ssl.SSLContext:
    """
    Creates and returns an SSL context that allows the use of unsigned certificates.

    Returns:
        ssl.SSLContext: An SSL context with the hostname verification disabled and certificate verification set to none.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def get_hostname_and_port(hostname, default_port):
    """
    Split the hostname and port if specified, otherwise use the default port.
    """
    if ":" in hostname:
        hostname, port = hostname.split(":")
        return hostname, int(port)
    else:
        return hostname, default_port


def clean_domains(domains: list) -> list:
    """
    Cleans a list of domains by removing any leading "*. " or "www." prefixes.

    Args:
        domains (list): A list of domain names.

    Returns:
        list: A list of cleaned domain names.

    """
    cleaned_domains = set()
    for domain in domains:
        if domain.startswith("*."):
            domain = domain[2:]
        if domain.startswith("www."):
            domain = domain[4:]
        cleaned_domains.add(domain)
    return list(cleaned_domains)


def get_certificate(hostname: str, port: int, timeout: int) -> crypto.X509:
    """
    Retrieves the X.509 certificate from the specified hostname and port.

    Args:
        hostname (str): The hostname of the server.
        port (int): The port number of the server.
        timeout (int): The timeout value for the connection.

    Returns:
        x509 (X509): The X.509 certificate object.

    Raises:
        HTTPException: If there is an error retrieving the certificate.
    """
    try:
        # Create an SSL context that allows the use of unsigned certificates
        context = allow_unsigned_certificate()

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
                # Retrieve the peer certificate in binary form and load it into an X.509 object
                cert = ssl_sock.getpeercert(binary_form=True)
                x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert)

                return x509
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))


def extract_subdomains(x509: crypto.X509) -> list:
    """
    Extracts subdomains and IP addresses from the certificate's subjectAltName extension.

    Args:
        x509 (X509): The X509 certificate object.

    Returns:
        list: A list of subdomains and IP addresses extracted from the certificate's subjectAltName extension.

    Raises:
        HTTPException: If an error occurs during the extraction process.
    """
    try:
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

        return subdomains
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(e))


def get_domains_recursive(
    hostname: str, port: int, seen_domains: Set[str], timeout: int, recursive: bool
) -> List[str]:
    """
    Recursively retrieves subdomains from a given hostname.

    Args:
        hostname (str): The hostname to retrieve subdomains from.
        port (int): The port number to use for the connection.
        seen_domains (set): A set of already seen domains to avoid infinite recursion.
        timeout (float): The timeout value for the connection.
        recursive (bool): Flag indicating whether to recursively retrieve subdomains.

    Returns:
        list: A list of cleaned subdomains extracted from the given hostname.
    """
    if hostname in seen_domains:
        return []
    seen_domains.add(hostname)

    # Get the certificate using the get_certificate function
    x509 = get_certificate(hostname, port, timeout)

    # Extract the domains using the extract_subdomains function
    domains = extract_subdomains(x509)

    if recursive:
        for domain in domains:
            if domain != hostname:
                try:
                    domains.extend(get_domains_recursive(domain, port, seen_domains, timeout, recursive))
                except HTTPException:
                    continue

    # Clean up the domains before returning them
    cleaned_domains = clean_domains(domains)
    return cleaned_domains


@app.get("/ssl_domains/{hostname}")
@limiter.limit("300/minute")
def get_ssl_domains(
    request: Request, hostname: str, recursive: bool = False, port: int = 443, timeout: int = 5
) -> dict:
    """
    Retrieve SSL domains for a given hostname.

    This endpoint returns a list of SSL domains associated with the specified hostname.
    The `hostname` parameter is required and represents the target hostname.
    The `recursive` parameter is optional and determines whether to recursively search for SSL domains.
    The `port` parameter is optional and specifies the port to use for the SSL connection (default is 443).
    The `timeout` parameter is optional and sets the timeout for the SSL connection (default is 5 seconds).

    Returns:
        A JSON containing the list of SSL domains.
    """
    seen_domains = set()
    domains = get_domains_recursive(hostname, port, seen_domains, timeout, recursive)
    return {hostname: domains}


@app.post("/ssl_domains/bulk")
@limiter.limit("300/minute")
def get_bulk_ssl_domains(request: Request, hostnames: Parameters) -> dict:
    bulk_results = {}
    failed_requests = []

    def process_hostname(hostname):
        hostname, port = get_hostname_and_port(hostname, hostnames.ssl_port)
        timeout = hostnames.timeout
        seen_domains = set()
        try:
            domains = get_domains_recursive(hostname, port, seen_domains, timeout, recursive=False)
        except HTTPException as e:
            failed_requests.append(hostname)
            return
        bulk_results[hostname] = domains

    with ThreadPoolExecutor() as executor:
        executor.map(process_hostname, hostnames.hostnames)

    data = {"domains_found": bulk_results, "failed_requests": failed_requests}
    return data


@app.get("/")
def get_home():
    return {
        "welcome_message": "Welcome to GSAN (Get SubjAltName) API!",
        "instructions": "To use this API, make a GET request to /ssl_domains/{hostname} endpoint. Provide the target hostname as a path parameter. For more information you can go to /docs or /redoc.",
        "about": "This API retrieves SSL domains associated with a given hostname. It uses the subjectAltName extension of the X.509 certificate to extract subdomains and IP addresses.",
        "limitations": "This API is rate-limited to 300 requests per minute. If the rate limit is exceeded, a 429 Too Many Requests response will be returned.",
        "disclaimer": "This API is for educational and informational purposes only. Use of this API is meant to demonstrate SSL domain extraction and should not be used for any malicious or harmful activities. All requests are logged for security and monitoring purposes.",
        "version": "0.1.0",
    }
