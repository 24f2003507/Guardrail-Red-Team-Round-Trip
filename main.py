from pathlib import Path
from urllib.parse import urlparse
import socket
import ipaddress

import requests
from fastapi import FastAPI
from pydantic import BaseModel


app = FastAPI()


SANDBOX_ROOT = Path(
    "/srv/agent-redteam/sandbox-b51b7ea541"
).resolve()


ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org"
}


class Request(BaseModel):
    tool: str
    arguments: dict



# -----------------------------
# Path security
# -----------------------------

def safe_path(user_path: str):

    requested = Path(user_path)

    # Convert absolute grader sandbox paths
    if str(requested).startswith(
        str(SANDBOX_ROOT)
    ):
        candidate = requested.resolve()

    else:
        candidate = (
            SANDBOX_ROOT / requested
        ).resolve()


    try:
        candidate.relative_to(
            SANDBOX_ROOT
        )

    except ValueError:
        raise Exception(
            "Path outside sandbox"
        )


    return candidate



def read_file(path):

    file_path = safe_path(path)


    if not file_path.exists():
        raise Exception(
            "File not found"
        )


    return file_path.read_text(
        encoding="utf-8"
    )



# -----------------------------
# URL security
# -----------------------------

def is_private(host):

    try:
        addresses = socket.getaddrinfo(
            host,
            None
        )

        for item in addresses:

            ip = item[4][0]

            addr = ipaddress.ip_address(ip)

            if (
                addr.is_private
                or addr.is_loopback
                or addr.is_link_local
                or addr.is_reserved
                or addr.is_unspecified
            ):
                return True

    except Exception:
        return True


    return False



def validate_url(url):

    parsed = urlparse(url)


    if parsed.scheme not in [
        "http",
        "https"
    ]:
        raise Exception(
            "Invalid scheme"
        )


    host = parsed.hostname


    if host is None:
        raise Exception(
            "Missing hostname"
        )


    host = host.lower()


    if host not in ALLOWED_HOSTS:
        raise Exception(
            "Host not allowed"
        )


    if is_private(host):
        raise Exception(
            "Private address blocked"
        )



def fetch_url(url):

    validate_url(url)


    response = requests.get(
        url,
        timeout=10,
        allow_redirects=False
    )


    if response.is_redirect:

        location = response.headers.get(
            "location"
        )

        if location:
            validate_url(location)


    return response.text



# -----------------------------
# Endpoint
# -----------------------------

@app.post("/check")
def check(req: Request):

    try:

        if req.tool == "read_file":

            result = read_file(
                req.arguments["path"]
            )

            return {
                "action": "allow",
                "reason": "sandbox file",
                "result": result
            }



        if req.tool == "fetch_url":

            result = fetch_url(
                req.arguments["url"]
            )

            return {
                "action": "allow",
                "reason": "allowed URL",
                "result": result
            }



        return {
            "action": "block",
            "reason": "unknown tool",
            "result": None
        }



    except Exception as e:

        return {
            "action": "block",
            "reason": str(e),
            "result": None
        }