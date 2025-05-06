from sqlalchemy import Column, String, Integer, create_engine, ForeignKey, Boolean, MetaData
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import sessionmaker
from config import settings
import uuid
from sqlalchemy.sql.sqltypes import TIMESTAMP
from sqlalchemy.sql.expression import text

SCHEMA_NAME = "auth"
metadata_obj = MetaData(schema=SCHEMA_NAME)
print(f"metadata: {metadata_obj.schema}")
Base = declarative_base(metadata=metadata_obj)
engine = create_engine(settings.DATABASE_URL)
sessionlocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    db = sessionlocal()
    try:
        yield db
    finally:
        db.close()

class User(Base):
    __tablename__= "users"
    __table_args__ = {'schema': SCHEMA_NAME}
    user_id = Column(String, primary_key=True, nullable=False, index=True,default=lambda: str(uuid.uuid4()))
    oauth_id = Column(String,unique=True, index=True)
    email_address = Column(String, nullable=False, unique=True, index=True)
    full_name = Column(String, nullable=False)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    verified_email = Column(Boolean, nullable=False)
    picture = Column(String) 
    provider = Column(String, nullable=False) 
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default= text('now()'))

class LoginDetails(Base):
    __tablename__="login_details"
    __table_args__ = {'schema': SCHEMA_NAME}
    login_details_id = Column(String, primary_key=True, nullable=False, index=True, default= lambda: str(uuid.uuid4()))
    user_id = Column(String,ForeignKey(f"{SCHEMA_NAME}.users.user_id"), nullable=False,index=True, unique=True)
    hashed_password = Column(String, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default= text("now()"))

class Project(Base):
    __tablename__="project"
    __table_args__={'schema': SCHEMA_NAME}
    project_id = Column(String, primary_key=True, nullable=False, index=True, default= lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey(f"{SCHEMA_NAME}.users.user_id"), nullable=False, index=True)
    project_name = Column(String, nullable=False, index=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text('now()'))
    permissions = Column(String, nullable=True, index=True)


class ProjectDetails(Base):
    __tablename__="project_details"
    __table_args__={'schema': SCHEMA_NAME}
    project_details_id =Column(String, primary_key=True, nullable=False, index=True, default= lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey(f"{SCHEMA_NAME}.users.user_id"), nullable=False, index=True)
    project_id = Column(String, ForeignKey(f"{SCHEMA_NAME}.project.project_id"), nullable=False, index=True, unique=True)
    secret_key_hash = Column(String, nullable=False, index=True, unique=True)
    msecret_key=Column(String, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text('now()'))

class HmacKeys(Base):
    __tablename__="hmac_keys"
    __table_args__={'schema': SCHEMA_NAME}
    hmac_id = Column(String, primary_key=True, nullable=False, index=True, default=lambda: str(uuid.uuid4()))
    project_id = Column(String, ForeignKey(f"{SCHEMA_NAME}.project_details.project_id"), nullable=False)
    hmac_version=Column(String, nullable=False, index=True)

class SaltVersion(Base):
    __tablename__="versioning"
    __table_args__={'schema': SCHEMA_NAME}
    version_id = Column(String, primary_key=True, nullable=False, index=True, default=lambda: str(uuid.uuid4()))
    version_name = Column(String, unique=True, nullable=False, index=True)
    key_value = Column(String, nullable=False)
    is_deprecated = Column(Boolean, nullable=False, default=False)



    
