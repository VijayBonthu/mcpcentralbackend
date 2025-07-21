from fastapi import APIRouter, Depends, HTTPException, status
from utils.logger import logger
from utils.token_generation import token_validator
from models import get_db
import models
from sqlalchemy.orm import Session
from p_model_type import AddServer
from sqlalchemy import and_


router = APIRouter()

@router.post("/add_server")
async def add_server(request: AddServer, db:Session=Depends(get_db), current_user:dict = Depends(token_validator)):
    #if request is empty throws the error)
    print(f"request: {request}")
    if current_user["regular_login_token"]["access_type"]!= "provider":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="You are not authorized to add a server")
    if not request or request.server_name == '':
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Provide details for all the mandatory fields")
    
    db.query = db.query(models.AddServers).filter_by(server_name = request.server_name).first()
    if db.query:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,detail=f"server name: {request.server_name} already exists")
    try:
        server_data = models.AddServers(
            server_name = request.server_name,
            description = request.description,
            author = request.author,
            version = request.version,
            server_url = request.server_url,
            server_type = request.server_type,
            server_api_key = request.server_api_key,
            modified_by = current_user["regular_login_token"]["id"],
            owned_by = current_user["regular_login_token"]["id"]
            )
        db.add(server_data)
        db.commit()
        db.refresh(server_data)
        logger.info(f"server {request.server_name} added successfully")
    except Exception as e:
        db.rollback()
        logger.error(f"Error while adding server: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"unable to add server: {str(e)}")
    
    return {"status":"Success", "message":f"Server {request.server_name} added successfully"}
    
@router.get("/get_all_servers/")
async def get_all_servers(db:Session=Depends(get_db), current_user:dict = Depends(token_validator)):
    if current_user['regular_login_token']['access_type']!='provider':
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="You are not authorized to view the servers")
    try:
        servers = db.query(models.AddServers).filter_by(owned_by = current_user['regular_login_token']['id']).all()
    except Exception as e:
        logger.error(f"Error while fetching servers: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"unable to fetch servers currently, please try after sometime")
    if not servers:
        return {"status":"Success", "message": "No servers found for the user, please add the servers"}
    servers_list = []
    for server in servers:
        server_data = {
            "server_id": server.server_id,
            "server_name": server.server_name,
            "description": server.description,
            "author": server.author,
            "version": server.version,
            "server_url": server.server_url,
            "server_type": server.server_type,
            "server_api_key": server.server_api_key,
            "owned_by":server.owned_by,
            "last_modified_by":server.modified_by,
            "last_modified_at":server.modified_at,
            "created_at":server.created_at
            }
        servers_list.append(server_data)
    return {"status":"Success", "message": "servers fetched successfully", "servers":servers_list}         
    
@router.get("/get_server/{server_id}")
async def get_server_details_by_id(server_id:str, db:Session=Depends(get_db), current_user:dict = Depends(token_validator)):
    if current_user['regular_login_token']['access_type']!='provider':
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="You are not authorized to view the servers")
    try:
        servers_by_server_id = db.query(models.AddServers).filter(and_(models.AddServers.owned_by == current_user['regular_login_token']['id']), (models.AddServers.server_id == server_id)).first()
    except Exception as e:
        logger.error(f"Error while fetching servers: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"unable to fetch servers currently, please try after sometime")
    if not servers_by_server_id:
        return {"status":"Success", "message": "No servers found for the user, please add the servers"}
    return {"status":"Success", "message": "servers fetched successfully", "servers":servers_by_server_id}         

@router.put("/update_server/{server_id}")
async def update_server(server_id: str, request: AddServer, db:Session=Depends(get_db), current_user:dict = Depends(token_validator)):
    #if request is empty throws the error
    if current_user["regular_login_token"]["access_type"]!= "provider":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="You are not authorized to update a server")
    if not request or request.server_name == "":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail = "provide details for all the mandatory fields")
    db.query = db.query(models.AddServers).filter(and_(models.AddServers.server_id == server_id, models.AddServers.owned_by == current_user["regular_login_token"]["id"])).first()
    if not db.query:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"server with id: {server_id} not found")
    try:
        db.query.server_name = request.server_name
        db.query.description = request.description
        db.query.author = request.author
        db.query.version = request.version
        db.query.server_url = request.server_url
        db.query.server_type = request.server_type
        db.query.server_api_key = request.server_api_key
        db.query.modified_by = current_user["regular_login_token"]["id"]
        db.commit()
        db.refresh(db.query)
        logger.info(f"server {request.server_name} updated successfully")
    except Exception as e:
        db.rollback()
        logger.error(f"Error while updating server: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"unable to update server: {str(e)}")
    return {"status": "Success", "message": f"Server {request.server_name} updated successfully"}
    
@router.delete("/delete_server/{server_id}")
async def delete_server(server_id:str, db:Session=Depends(get_db), current_user:dict = Depends(token_validator)):
    if current_user['regular_login_token']['access_type']!='provider':
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="You are not authorized to delete a server")
    try:
        db.query(models.AddServers).filter(and_(models.AddServers.server_id == server_id),(models.AddServers.owned_by == current_user["regular_login_token"]["id"])).delete()
        db.commit()
        logger.info(f"server with id: {server_id} deleted successfully")
    except Exception as e:
        db.rollback()
        logger.error(f"Error while deletting server: {e}")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"unable to delete the server, please try after sometime.")
    return {"status": "Success", "message": f"Server with id: {server_id} deleted successfully"}
        
    