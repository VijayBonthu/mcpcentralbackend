from oauth import flow, auth_callback
from fastapi import Depends, HTTPException, Request, APIRouter, status
from models import get_db
from sqlalchemy.orm import Session
from database_scripts import create_user,UserCreationError, get_user_details
from utils.token_generation import create_token, verify_password, TokenDecoder, validate_app_user
from p_model_type import Registration_login_password, login_details
import logging
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials


logger = logging.getLogger(__name__)

router = APIRouter()

security = HTTPBearer()

auth_states = {}
@router.get("/auth/login")
async def login():
    result= flow.authorization_url(prompt="consent")

    auth_url = result[0] if isinstance(result, tuple) else result
    state = result[1] if isinstance(result, tuple) else None

    if state:
        auth_states[state] = True
    print(auth_url)
    return RedirectResponse(url=auth_url)

@router.get("/auth/callback", status_code=status.HTTP_200_OK)
async def callback(request: Request, db:Session=Depends(get_db)):
    # Extract the state from query parameters
    state = request.query_params.get("state")
    logger.info(f"State: {state}")
    if not state or state not in auth_states:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Link already expired, Try to login in again")
    try: 
        #Uses Google authentication to login
        logger.info(f"Request URL: {request.url}")
        response =auth_callback(url=request.url)
        logger.info(f"Response: {response}")
        if response.get("message") == "bad request":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Issue with your login, Please try again")
        user_data = response["user"]
    except UserCreationError as e:
        #add logging here to save it
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Something went wrong, it is not you, Please try after sometime")
    try:
        #create a record in DB if its the first time or get the details for jwt payload
        user = await create_user(user_data=user_data,provider=response['provider'], db=db)
        auth_states.pop(state,None)
        #add logging here to save it
    except UserCreationError as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Something went wrong, it is not you, Please try after sometime") 
    
    payload= {
        "id": user.user_id,
        "oauth_id": user.oauth_id,
        "verified_email":user.verified_email,
        "picture": user.picture,
        "provider": user.provider,
        "email":user.email_address
    }
     # creates JWT token
    token = create_token(user_data=payload)
    print(token)
    
    # Return HTML instead of JSON
    html_content = f"""
    <html>
    <head><title>Authentication Complete</title></head>
    <body>
        <h2>Authentication Successful!</h2>
        <p>You can close this window and return to the application.</p>
        
        <script>
            // Send token back to opener window
            if (window.opener) {{
                window.opener.postMessage(
                    {{ 
                        type: 'google_auth_success', 
                        access_token: '{token}'
                    }},
                    '*'  // In production, you should limit this to your app's origin
                );
                
                // Close this window after a delay
                setTimeout(() => window.close(), 3000);
            }}
        </script>
    </body>
    </html>
    """
    
    return HTMLResponse(content=html_content)

@router.post("/registration", status_code=status.HTTP_201_CREATED)
async def create_account(user_details:Registration_login_password, db:Session=Depends(get_db)):
    if not user_details:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Required details are not provided")
    if user_details.access_type.lower() == "user": 
        try:
            user_details = user_details.__dict__
            user_details.update(
                {
                    "id": None,
                    "verified_email":False,
                    "picture":None,
                    "provider":"Local",
                    "name":user_details["given_name"] + " " +user_details["family_name"]
                }
            )
            print(f"user_details_user: {user_details}")
            user = await create_user(user_data=user_details, provider="Local",db=db)
        except UserCreationError as e:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Something went wrong, it is not you, Please try after sometime{e}")
    elif user_details.access_type.lower() == "provider":
        try:
            user_details = user_details.__dict__
            user_details.update(
                {
                    "id": None,
                    "verified_email":False,
                    "picture":None,
                    "provider":"Local",
                    "name":user_details["given_name"] + " " +user_details["family_name"]
                }
            )
            print(f"user_details_provider: {user_details}")
            user = await create_user(user_data=user_details, provider="Local",db=db)
        except UserCreationError as e:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"Something went wrong, it is not you, Please try after sometime{e}")
    payload= {
        "id": user.user_id,
        "verified_email":user.verified_email,
        "access_type":user.access_type,
        "picture": user.picture,
        "provider": user.provider,
        "email":user.email_address
    }
    try:
        token = create_token(user_data=payload)
        print(token)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail = f" error creating token: {str(e)}")
    return {"access_token": token, "token_type": "bearer"} 

@router.post("/login", status_code=status.HTTP_200_OK)
def log_into_account(login_details:login_details, db:Session=Depends(get_db)):
    if not login_details:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Please provide the details to login")
    try:
        user_details = get_user_details(email_address=login_details.email_address, access_type=login_details.access_type, db=db)
        print(f"user_details: {user_details}")
    except UserCreationError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Record doesn't exists, please register to Login")
    checked_password = verify_password(password=login_details.password,hashed_password=user_details["hashed_password"])
    if checked_password:
        payload= {
            "id": user_details["user_id"],
            "verified_email":user_details["verified_email"],
            "provider": user_details["provider"],
            "email":user_details["email_address"],
            "access_type": user_details['access_type']
        }
        token = create_token(user_data=payload)
        print(token)
        return {"access_token": token, "token_type": "bearer"}
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    
@router.get("/decode_token/{token}")
async def decode_token(token:str):
    token_decoder = TokenDecoder()
    return await token_decoder.decode_oauth_token(token=token)

@router.get("/validate_token")
async def validate_token(credentials: Request):
    
    if credentials.headers.get("Authorization") is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token is missing")
    if credentials.headers.get("Authorization").startswith("Bearer "):
        token = credentials.headers.get("Authorization").split(" ")[1]
    else:
        token = credentials.headers.get("Authorization")
    return await validate_app_user(token)


