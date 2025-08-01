from jose import jwt, JWTError
from datetime import datetime, timedelta, timezone
from config import settings
from fastapi import status, HTTPException,Security, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
import base64
import json
from utils.logger import logger

UPLOADS_DIR = "uploads"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

def create_token(user_data:dict):
    try:
        to_encode = user_data.copy()
        to_encode.update({
            "iat":datetime.now(timezone.utc),
            "exp":datetime.now(timezone.utc) + timedelta(days=int(settings.TOKEN_EXPIRED_TIME_IN_DAYS))
        })
        return jwt.encode(
            to_encode, 
            settings.SECRET_KEY_J, 
            algorithm=settings.ALGORITHM)
    except JWTError as e:
        raise Exception(f"Failed to create token: {str(e)}")

async def validate_token(token:str, credential_exception):
    try:
        if not token:
            raise Exception(f"No token provided in the header")
    #change has been made in key for all auths if it doesnt work remove secrets from paramters and key and replace it with settings.SECRET_KEY_J
        payload = jwt.decode(
            token=token,
            key=settings.SECRET_KEY_J,
            algorithms=settings.ALGORITHM
            )
        
        exp = payload.get("exp")
        if not exp or datetime.fromtimestamp(exp, tz=timezone.utc)<datetime.now(timezone.utc):
            raise credential_exception
        return payload
    except JWTError:
        raise credential_exception

async def validate_token_incoming_requests(token:str):
    try:
        if not token:
            raise Exception(f"No token provided in the header")
    #change has been made in key for all auths if it doesnt work remove secrets from paramters and key and replace it with settings.SECRET_KEY_J
        payload = jwt.decode(
            token=token,
            key=settings.SECRET_KEY_J,
            algorithms=settings.ALGORITHM
            )
        exp = payload.get("exp")
        if not exp or datetime.fromtimestamp(exp, tz=timezone.utc)<datetime.now(timezone.utc):
            raise Exception(f"token expired")
        return payload
    except JWTError as e:
        raise Exception(f"failed to validate token: {str(e)}")
    
def get_current_user(token: HTTPAuthorizationCredentials = Security(security)):
    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    return validate_token(token.credentials, credential_exception)

async def token_validator(request: Request,token: HTTPAuthorizationCredentials = Security(security)):

    
    logger.info(f"request headers: {request.headers}")
    logger.info(f"token: {token}")
    regular_token = await validate_app_user(token = token.credentials)
    return {"regular_login_token": regular_token}

def hash_passwords(password:str):
    return pwd_context.hash(password)

def verify_password(password:str, hashed_password:str):
    [print(f"password: {password}, hashed_password: {hashed_password}")]
    return pwd_context.verify(password,hashed_password)


def validate_jira_token(token: str):
    """Validate Jira-specific JWT token"""
    try:
        payload = jwt.decode(
            token=token,
            key=settings.SECRET_KEY_J,
            algorithms=settings.ALGORITHM
        )
        
        # Check if it's a Jira token
        if payload.get("provider") != "Jira":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Jira token"
            )
            
        # Check expiration
        exp = payload.get("exp")
        if not exp or datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Jira token has expired"
            )
            
        return payload
        
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid Jira token: {str(e)}"
        )
class TokenDecoder:
    @staticmethod
    async def decode_oauth_token(token: str):
        try:
            parts = token.split('.')
            if  len(parts) != 3:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format")
            
            padded = parts[1] + '=' *(4-len(parts[1]) % 4)
            payload = base64.b64decode(padded)
            return json.loads(payload)
        except Exception as e:
            logger.error(f"Error decoding token: {str(e)}")
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token format")

async def validate_app_user(token:str):
    """Validate the app's JWT token"""
    credential_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    try:
        # token = credentials.credentials
        token = token
        logger.info(f"token: {token}")
        token_decoder = TokenDecoder()
        payload = await token_decoder.decode_oauth_token(token=token)
        logger.info(f"payload: {payload}")

        return await validate_token(token=token, credential_exception=credential_exception)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"error {str(e)}")
