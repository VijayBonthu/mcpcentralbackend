import models
from models import get_db
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session
from p_model_type import Registration_login
from sqlalchemy import and_
from utils.token_generation import hash_passwords
from fastapi import HTTPException, status

class UserCreationError(Exception):
    pass

async def create_user(user_data:dict,provider:str, db:Session):
    # {'id': '106124317363210854486', 'email': '@gmail.com', 'verified_email': True, 'name': 'full name', 'given_name': 'first name', 'family_name': 'last name', 'picture': 'https://lh3.googleusercontent.com/a/ACg8ocKaB3SgzhN1nS059s7D1re6z0eTnG6wtUDl5A695G-8Akhvq5GD'}
    # {'email': '123@123.com', 'given_name': '123', 'family_name': '456', 'name': '123 456', 'password': 'string', 'id': None, 'verified_email': False, 'picture': None, 'provider': 'Local'}
    if not user_data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,detail="Required details not provided")
    if user_data["access_type"].lower() == "user":
        print(f"user creation inside access_type: user")
        try:
            query = db.query(models.User).filter(and_(models.User.email_address == user_data["email"], models.User.provider == provider))
            user_details = query.first()
            if user_details and user_details.provider == "Local":
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Record already Exists, try logging into the account")
        except SQLAlchemyError as e:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"unable to connect to DB {e}")
        
        if not user_details:
            user_details = models.User(
                oauth_id = user_data["id"],
                email_address = user_data["email"],
                first_name = user_data["given_name"],
                last_name = user_data["family_name"],
                access_type = user_data["access_type"],
                verified_email = user_data["verified_email"],
                full_name = user_data["name"],
                picture = user_data["picture"],
                provider = provider
            )
            try: 
                db.add(user_details)
                db.commit()
                db.refresh(user_details)
                
            except SQLAlchemyError as e:
                db.rollback() 
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,detail=f"unable to create details: {str(e.args), str(e.code)}")

            if user_details.provider == "Local":
                h_pass = hash_passwords(password=user_data["password"]) 
                password_details = models.LoginDetails(
                    user_id = user_details.user_id,
                    hashed_password = h_pass
                )
                try:
                    db.add(password_details)
                    db.commit()
                except SQLAlchemyError as e:
                    db.rollback() 
                    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"unable to create details: {str(e)}")
            return user_details
        return user_details
    
    elif user_data["access_type"].lower() == "provider":
        print(f"user creation inside access_type: provider")
        try:
            query = db.query(models.ProviderUser).filter(and_(models.ProviderUser.email_address == user_data["email"]), provider == models.ProviderUser.provider)
            user_details = query.first()
            if user_details and user_details.provider == "Local":
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Record already Exists, try logging into the account")
        except SQLAlchemyError as e:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=f"unable to connect to DB {e}")
        
        if not user_details:
            user_details = models.ProviderUser(
                oauth_id = user_data["id"],
                email_address = user_data["email"],
                first_name = user_data["given_name"],
                last_name = user_data["family_name"],
                access_type = user_data["access_type"],
                verified_email = user_data["verified_email"],
                full_name = user_data["name"],
                picture = user_data["picture"],
                provider = provider
            )
            try: 
                db.add(user_details)
                db.commit()
                db.refresh(user_details)
                
            except SQLAlchemyError as e:
                db.rollback() 
                raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,detail=f"unable to create details: {str(e.args), str(e.code)}")

            if user_details.provider == "Local":
                h_pass = hash_passwords(password=user_data["password"]) 
                password_details = models.ProviderLoginDetails(
                    user_id = user_details.user_id,
                    hashed_password = h_pass
                )
                try:
                    db.add(password_details)
                    db.commit()
                except SQLAlchemyError as e:
                    db.rollback() 
                    raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"unable to create details: {str(e)}")
            return user_details
        return user_details

def get_user_details(email_address:str, access_type:str, db:Session):
    """Get user details by email address"""
    if access_type.lower() == "user":
        try:
            query = db.query(models.User.email_address,
                            models.User.user_id,
                            models.User.first_name,
                            models.User.last_name,
                            models.User.verified_email,
                            models.User.access_type,
                            models.User.provider,
                            models.LoginDetails.hashed_password
                            ).join(
                                models.LoginDetails,
                                models.User.user_id == models.LoginDetails.user_id) 
            record = query.filter(and_(
                models.User.provider=="Local", models.User.verified_email == "False", models.User.email_address == email_address
            )).first()
            print(f"record: {record}")
        except SQLAlchemyError as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Something wrong with our service, please try again later")
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Details not found, please register your account")
        return {
            "email_address": record[0],
            "user_id":record[1],
            "first_name":record[2],
            "last_name":record[3],
            "verified_email":record[4],
            "access_type":record[5],
            "provider":record[6],
            "hashed_password":record[7]
        }
    elif access_type.lower()== "provider":
        try:
            query = db.query(models.ProviderUser.email_address,
                            models.ProviderUser.user_id,
                            models.ProviderUser.first_name,
                            models.ProviderUser.last_name,
                            models.ProviderUser.verified_email,
                            models.ProviderUser.access_type,
                            models.ProviderUser.provider,
                            models.ProviderLoginDetails.hashed_password
                            ).join(
                                models.ProviderLoginDetails,
                                models.ProviderUser.user_id == models.ProviderLoginDetails.user_id) 
            record = query.filter(and_(
                models.ProviderUser.provider=="Local", models.ProviderUser.verified_email == "False", models.ProviderUser.email_address == email_address
            )).first()
            print(f"record: {record}")
        except SQLAlchemyError as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Something wrong with our service, please try again later")
        if not record:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Details not found, please register your account")
        return {
            "email_address": record[0],
            "user_id":record[1],
            "first_name":record[2],
            "last_name":record[3],
            "verified_email":record[4],
            "access_type":record[5],
            "provider":record[6],
            "hashed_password":record[7]
        }



async def user_documents(doc_data:dict, db:Session) -> dict:
    if not doc_data:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No document data found with valid user_id found")
    document_details = models.UserDocuments(
        user_id = doc_data["user_id"],
        document_path = doc_data["document_path"]
    )
    try:
        db.add(document_details)
        db.commit()
        db.refresh(document_details)
        return {"document_id":document_details.document_id,"document_path":document_details.document_path,"user_id":document_details.user_id}
    except SQLAlchemyError as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"unable to create document data {str(e)}")
    

