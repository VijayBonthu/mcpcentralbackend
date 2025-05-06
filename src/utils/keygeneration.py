import secrets
import uuid
import hmac
import hashlib
from typing import Literal

def generate_api_key(project_name:str, server_details:Literal["dev", "prod"] = "dev")->str:
    if server_details == "dev":
        prefix = f"ak-{server_details}-{project_name[:4]}-{uuid.uuid4().hex[:8]}"
        token = secrets.token_urlsafe(32)
        return f"{prefix}.{token}"
    elif server_details == "prod":
        prefix = f"ak-{server_details}-{project_name[:4]}-{uuid.uuid4().hex[:8]}"
        token = secrets.token_urlsafe(32)
        return f"{prefix}.{token}"
    else:
        raise ValueError("Invalid server details it can only be prod or dev")
    
def mask_key(key:str)->str:
    return f"{key[:20]}.............{key[-4:]}"

async def hash_with_hmac(api_key:str, salt:str)->str:
    secret = salt
    return hmac.new(secret.encode(),api_key.encode(),hashlib.sha256).hexdigest()