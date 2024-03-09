from fastapi import FastAPI
import ssl
import socket

from fastapi import HTTPException

app = FastAPI()


def clean_domains(domains, seen_domains=None):
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


def get_domains(hostname: str, port: int, seen_domains):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
                cert = ssl_sock.getpeercert()
                domains = [san[1] for san in cert["subjectAltName"] if san[0].startswith("DNS")]
                cleaned_domains, seen_domains = clean_domains(domains, seen_domains)
                return cleaned_domains, seen_domains
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/ssl_domains/{hostname}")
def get_ssl_domains(hostname: str, recursive: bool = False, port: int = 443):
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
