from sqlalchemy import Column, String, Integer, create_engine, ForeignKey, Boolean, MetaData, UniqueConstraint, CheckConstraint
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
    access_type = Column(String, nullable=False)
    full_name = Column(String, nullable=False)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    verified_email = Column(Boolean, nullable=False)
    picture = Column(String)
    provider = Column(String, nullable=False) 
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default= text('now()'))

class ProviderUser(Base):
    __tablename__= "provider_users"
    __table_args__ = {'schema': SCHEMA_NAME}
    user_id = Column(String, primary_key=True, nullable=False, index=True,default=lambda: str(uuid.uuid4()))
    oauth_id = Column(String,unique=True, index=True)
    email_address = Column(String, nullable=False, unique=True, index=True)
    access_type = Column(String, nullable=False)
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

class ProviderLoginDetails(Base):
    __tablename__="provider_login_details"
    __table_args__ = {'schema': SCHEMA_NAME}
    login_details_id = Column(String, primary_key=True, nullable=False, index=True, default= lambda: str(uuid.uuid4()))
    user_id = Column(String,ForeignKey(f"{SCHEMA_NAME}.provider_users.user_id"), nullable=False,index=True, unique=True)
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

# class BillingRate(Base):
#     __tablename__="versioning"
#     __table_args__={'schema': SCHEMA_NAME}
#     billing_rate_id = Column(String, primary_key=True, nullable=False, index=True, default=lambda: str(uuid.uuid4()))
#     subscription_type=Column(String, unique=True, index=True, nullable=False)
#     subscription_amount = Column(float, nullable=False)
#     perks = Column(String, nullable=False, index=True)
#     created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text('now()'))
#     created_by = Column(String, nullable=False)
#     modified_by = Column(String, nullable=False)

class AddServers(Base):
    __tablename__ = 'add_servers'
    __table_args__ = (
        UniqueConstraint('server_url', 'server_name', 'version', 'author', name='add_servers_url_version_uc'),
        CheckConstraint("position(' ' in server_name) = 0", name='no_spaces_in_server_name'),
        {'schema': SCHEMA_NAME}
        )
    server_id = Column(String, primary_key=True, nullable=False, index=True, default=lambda: str(uuid.uuid4()))
    server_name = Column(String, nullable=False,index=True)
    description= Column(String, nullable=False)
    author = Column(String, nullable=False, index=True)
    version = Column(String, nullable=False, index=True)
    server_url = Column(String, nullable=False, unique=True, index=True)
    server_type= Column(String, nullable=False, default='function')
    server_api_key = Column(String, index=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text('now()'))
    modified_at = Column(TIMESTAMP(timezone=True), nullable=False, server_default=text('now()'), onupdate=text('now()'))
    modified_by = Column(String, nullable=False)
    owned_by = Column(String, ForeignKey(f"{SCHEMA_NAME}.provider_users.user_id"), nullable=False, index=True)









    
