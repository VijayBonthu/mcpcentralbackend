from pydantic import BaseModel, field_validator
from typing import Optional, List, Dict, Literal
import re

class UploadDoc(BaseModel):
    expected_time:str = None
    list_of_developers:Optional[list[str]] = None

class Registration_login(BaseModel):
    email:str
    id:str = None
    given_name:str
    family_name:str
    verified_email:bool=False
    name:str
    picture:str = None
    provider:str = None

class Registration_login_password(BaseModel):
    email:str
    given_name:str
    family_name:str
    password:str
    access_type:Literal["user", "provider"] = 'user'

class login_details(BaseModel):
    email_address:str
    password:str
    access_type:Literal['user', 'provider'] = 'user'

class Project(BaseModel):
    name:str
    server_environment:str='prod'
    permissions:Optional[List[str]]=None

class AddServer(BaseModel):
    server_name: str #cant have spaces in name
    
    description: str
    author: str
    version: str
    server_url: str
    server_type: str = "function"
    server_api_key: str

    @field_validator('server_name')
    def no_spaces(cls,value):
        if " " in value:
            raise ValueError('Server_name cannot contain spaces')
        return value
    
    @field_validator('version')
    def valid_version(cls, value):
        if not re.match(r'^\d+\.\d+\.\d+$', value):
            raise ValueError("version must be in the formar X.Y.Z(e.g., 1.0.0)")
        return value
