from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from os import getenv
from dotenv import load_dotenv

load_dotenv()


POSTGRES_URL = getenv('POSTGRES_URL')
engine = create_engine(POSTGRES_URL)
SessionLocal = sessionmaker(autoflush=True, bind=engine)

Base = declarative_base()
