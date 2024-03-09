from fastapi import FastAPI
import ssl
import socket
from os import environ

from fastapi import HTTPException, Depends, status, Header

app = FastAPI()


def get_api_key(api_key: str = Header(None)):
    if api_key is None or api_key != environ.get("API_KEY"):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
    return api_key


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


def get_domains(hostname: str, port: int, seen_domains) -> tuple:
    """
    Retrieves the domains from the SSL certificate of the specified hostname and port.

    Args:
        hostname (str): The hostname of the server.
        port (int): The port number of the server.
        seen_domains: A list of domains that have already been seen.

    Returns:
        Tuple[List[str], List[str]]: A tuple containing the cleaned domains and the updated list of seen domains.

    Raises:
        HTTPException: If an error occurs while retrieving the domains.
    """
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
                cert = ssl_sock.getpeercert()
                domains = [san[1] for san in cert["subjectAltName"] if san[0].startswith("DNS")]
                cleaned_domains, seen_domains = clean_domains(domains, seen_domains)
                return cleaned_domains, seen_domains
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.get("/ssl_domains/{hostname}")
def get_ssl_domains(hostname: str, recursive: bool = False, port: int = 443, api_key: str = Depends(get_api_key)):
    seen_domains = set()
    domains, seen_domains = get_domains(hostname, port, seen_domains)
    sub_domains = []
    if recursive:
        for domain in domains:
            if domain != hostname:
                try:
                    new_sub_domains, seen_domains = get_domains(domain, port, seen_domains)
                    sub_domains.extend(new_sub_domains)
                except HTTPException:
                    continue
    return {"domains": domains + sub_domains}
