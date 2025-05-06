from fastapi import APIRouter, Depends, HTTPException, status
from utils.logger import logger
from utils.token_generation import token_validator
from models import get_db
import models
from sqlalchemy.orm import Session
from p_model_type import Project
from sqlalchemy import and_
from utils.keygeneration import generate_api_key, mask_key, hash_with_hmac
import random

router = APIRouter()

@router.post("/project")
async def create_project(request:Project, db:Session=Depends(get_db), current_user:dict = Depends(token_validator)):
    #If request is empty throws the error
    if not request or request.name == '':
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="provide details for all the mandatatory fields")
    
    # Checks if the project name already exists for the user
    query = db.query(models.Project).filter(and_(models.Project.project_name == request.name), (models.Project.user_id == current_user["regular_login_token"]["id"]))
    result = query.first()
    if result:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=f"project name already exist, project name should be unique")
    
    # Fetch a non deprecated salt version and selects a random version for salting the api key generated
    secret_query = db.query(models.SaltVersion).filter_by(is_deprecated=False).all()
    secret_version = random.choice(secret_query)

    #Generate API Key and hash it and create a masked api key
    while True:
        api_key=generate_api_key(request.name, server_details=request.server_environment)
        hash_api_key = await hash_with_hmac(api_key=api_key,salt=secret_version.key_value)

        existing_key = db.query(models.ProjectDetails).filter_by(secret_key_hash=hash_api_key).first()
        if not existing_key:
            break
    mask_api_key =mask_key(api_key)

    logger.info(f"All required keys and versions generated")
    user_project_data = models.Project(
        user_id=current_user["regular_login_token"]["id"],
        project_name=request.name,
        permissions= request.permissions
    )

    try:
        db.add(user_project_data)
        db.commit()
        db.refresh(user_project_data)
        logger.info("Project successfully created")

    # If project successfully created then proceeds to create project Details
        if user_project_data:
            project_details_content = models.ProjectDetails(
            project_id=user_project_data.project_id,
            user_id=current_user["regular_login_token"]["id"],
            secret_key_hash=hash_api_key,
            msecret_key=mask_api_key
            )
            db.add(project_details_content)
            db.commit()
            db.refresh(project_details_content)
    # if project Details are created then proceeds to create Hmacdetails for saving the version of the salt used to hash the user api key
            if project_details_content:
                hmac_details = models.HmacKeys(
                    project_id=user_project_data.project_id,
                    hmac_version=secret_version.version_name
                )
                db.add(hmac_details)
                db.commit()
            return {'message': "data successfully added and project and apikeys are created",
                    'content': {'user_id': current_user["regular_login_token"]["id"],
                                'project_id': user_project_data.project_id,
                                'api_key':api_key,
                                'masked_api_key': mask_api_key,
                                'created_at': user_project_data.created_at,
                                'permissions': request.permissions}}
    except Exception as e:
        db.rollback()
        logger.error(f"Error occur when creating the new project. user_id {current_user["regular_login_token"]["id"]}, project_name:{request.name}, error: {str(e)} ")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Service is currently facing an issue Please try again after sometime")
    
@router.get("/project/{api_key}")
async def get_api_key_details(api_key:str,db:Session=Depends(get_db)):
    if not api_key:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="API key is missing")
    masked_api_key = mask_key(key=api_key)

    api_details = db.query(models.ProjectDetails).filter_by(msecret_key=masked_api_key).first()
    if not api_details:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid API Keys")
    
    salt_versioning_data = db.query(models.HmacKeys.hmac_version, models.SaltVersion.version_name, models.SaltVersion.key_value).join(models.SaltVersion, models.HmacKeys.hmac_version == models.SaltVersion.version_name).filter(models.HmacKeys.project_id == api_details.project_id).first()
    if salt_versioning_data:
        hmac_version, version_name, key_value = salt_versioning_data
    else:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Salt version not found")
    hashed_api_key_details = await hash_with_hmac(api_key=api_key, salt=key_value)
    if hashed_api_key_details == api_details.secret_key_hash:
        return {
            "status": "valid",
            "user_id": api_details.user_id,
            "project_id": api_details.project_id
        }
    else:
        return {
            "status": "invalid"
        }


    
    



