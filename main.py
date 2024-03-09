from fastapi import FastAPI
import ssl
import socket

from fastapi import HTTPException

app = FastAPI()


def clean_domains(domains):
    cleaned_domains = set()
    for domain in domains:
        if domain.startswith("*."):
            domain = domain[2:]
        cleaned_domains.add(domain)
    return list(cleaned_domains)


@app.get("/ssl_domains/{hostname}")
def get_ssl_domains(hostname: str, port: int = 443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssl_sock:
                cert = ssl_sock.getpeercert()
                domains = [san[1] for san in cert["subjectAltName"] if san[0].startswith("DNS")]
                cleaned_domains = clean_domains(domains)
                return {"domains": cleaned_domains}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
