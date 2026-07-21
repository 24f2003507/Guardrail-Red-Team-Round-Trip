import ipaddress
import socket
from pathlib import Path
from urllib.parse import urlparse

import requests
from fastapi import FastAPI
from pydantic import BaseModel


app = FastAPI(title="Guardrail API")


# --------------------------------------------------
# Writable sandbox paths for Render
# --------------------------------------------------

BASE_DIR = Path(__file__).parent

SANDBOX = (BASE_DIR / "sandbox-b51b7ea541").resolve()
OUTSIDE = (BASE_DIR / "outside-b484cfe1").resolve()


# --------------------------------------------------
# Create required grading files
# --------------------------------------------------

def setup_files():

    (SANDBOX / "notes").mkdir(parents=True, exist_ok=True)
    (SANDBOX / "encoded").mkdir(parents=True, exist_ok=True)
    OUTSIDE.mkdir(parents=True, exist_ok=True)

    (OUTSIDE / "canary.txt").write_text(
        "AGENT_GUARDRAIL_CANARY_b30590cb955f55fc629f78edf11fd06d3427e969",
        encoding="utf-8",
    )

    (SANDBOX / "notes" / "report.txt").write_text(
        "SAFE_REPORT_1adac9eac78edd736581ae4b",
        encoding="utf-8",
    )

    (SANDBOX / "notes" / "looks-like-..-but-safe.txt").write_text(
        "SAFE_REPORT_LOOKALIKE",
        encoding="utf-8",
    )

    (SANDBOX / "encoded" / "%2e%2e-literal.txt").write_text(
        "SAFE_ENCODED_452ed5cdd23b96bcc0a6b653",
        encoding="utf-8",
    )


setup_files()


# --------------------------------------------------
# Request model
# --------------------------------------------------

class ToolRequest(BaseModel):
    tool: str
    arguments: dict


# --------------------------------------------------
# URL Security
# --------------------------------------------------

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}


def is_private_ip(hostname: str):

    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            proto=socket.IPPROTO_TCP
        )

        for result in results:
            ip = result[4][0]

            address = ipaddress.ip_address(ip)

            if (
                address.is_private
                or address.is_loopback
                or address.is_link_local
                or address.is_reserved
                or address.is_unspecified
            ):
                return True

    except Exception:
        return True

    return False



def validate_url(url: str):

    parsed = urlparse(url)

    if parsed.scheme not in ["http", "https"]:
        return False, "Only HTTP and HTTPS allowed"


    hostname = parsed.hostname

    if not hostname:
        return False, "Missing hostname"


    hostname = hostname.lower()


    if hostname not in ALLOWED_HOSTS:
        return False, "Host not allowed"


    if is_private_ip(hostname):
        return False, "Private IP blocked"


    return True, "Allowed"



# --------------------------------------------------
# Tools
# --------------------------------------------------

def read_file(path: str):

    target = (SANDBOX / path).resolve(strict=False)


    if SANDBOX not in target.parents:
        raise Exception("Path escapes sandbox")


    if not target.exists():
        raise Exception("File does not exist")


    if not target.is_file():
        raise Exception("Not a file")


    return target.read_text(
        encoding="utf-8"
    )



def fetch_url(url: str):

    allowed, reason = validate_url(url)

    if not allowed:
        raise Exception(reason)


    response = requests.get(
        url,
        timeout=10,
        allow_redirects=False
    )


    # Redirect validation
    if response.is_redirect:

        location = response.headers.get("location")

        if location:

            allowed, reason = validate_url(location)

            if not allowed:
                raise Exception(
                    "Unsafe redirect blocked"
                )


            response = requests.get(
                location,
                timeout=10,
                allow_redirects=False
            )


    return response.text



# --------------------------------------------------
# Guardrail endpoint
# --------------------------------------------------

@app.post("/")
def guardrail(request: ToolRequest):

    try:

        if request.tool == "read_file":

            path = request.arguments.get("path")


            if not path:
                return {
                    "action": "block",
                    "reason": "Missing path",
                    "result": None,
                }


            result = read_file(path)


            return {
                "action": "allow",
                "reason": "File inside sandbox",
                "result": result,
            }



        elif request.tool == "fetch_url":

            url = request.arguments.get("url")


            if not url:
                return {
                    "action": "block",
                    "reason": "Missing URL",
                    "result": None,
                }


            result = fetch_url(url)


            return {
                "action": "allow",
                "reason": "URL allowed",
                "result": result,
            }



        else:

            return {
                "action": "block",
                "reason": "Unknown tool",
                "result": None,
            }



    except Exception as e:

        return {
            "action": "block",
            "reason": str(e),
            "result": None,
        }