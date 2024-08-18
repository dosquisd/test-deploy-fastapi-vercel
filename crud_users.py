import models, schemas
from sqlalchemy.orm import Session
from fastapi import HTTPException, status

from passlib.context import CryptContext
from os import getenv
from dotenv import load_dotenv

load_dotenv()

pwd_context = CryptContext(schemes=[getenv("CRYPT_CONTEXT_SCHEME")], deprecated=["auto"])


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """ Verifies that a plain text password matches the hashed password stored in the database.

    Args:
        plain_password (str): The password entered by the user in plain text.
        hashed_password (str): The hashed password stored in the database.

    Returns:
        bool: True if the plain text password matches the hashed password, otherwise False.
     """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Hashes a plain text password using the password context.

    Args:
        password (str): The plain text password to be hashed.

    Returns:
        str: The hashed password.
    """
    return pwd_context.hash(password)


def get_user(db: Session, username: str) -> models.ActiveUser | None:
    """
    Retrieves a user from the active users table based on the username.

    Args:
        db (Session): The database session used to query the database.
        username (str): The username of the user to be retrieved.

    Returns:
        models.ActiveUser | None: The user record from the active users table
            if found, otherwise None.
    """
    return db.query(models.ActiveUser).filter(models.ActiveUser.username == username).first()


def authenticate_user(db: Session, username: str, password: str) -> models.ActiveUser | None:
    """
    Authenticates a user by checking the provided username and password
    against the records in the active users table.

    Args:
        db (Session): The database session used to query the database.
        username (str): The username of the user to authenticate.
        password (str): The plain text password to verify.

    Returns:
        models.ActiveUser | None: The user record from the active users table
            if the credentials are valid, otherwise None.
    """
    user_db = get_user(db, username)
    if user_db is None:
        return None
    if not verify_password(password, user_db.password):
        return None
    return user_db


def create_user(db: Session, user: schemas.User) -> models.ActiveUser:
    """
    Creates a new user in the system by adding them to the active users table.
    If the user already exists or if the DNI is currently in use, appropriate
    exceptions are raised.

    Args:
        db (Session): The database session used to query and modify the database.
        user (schemas.User): The user data to be added, including DNI, username,
            password, and kind.

    Returns:
        models.ActiveUser: The newly created user record in the active users table.

    Raises:
        HTTPException: If the username is already registered or if the DNI is 
            currently in use by an active user.
    """
    if get_user(db, user.username) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, '¡Usuario ya registrado!')

    hashed_password = get_password_hash(user.password)
    db_user_dni: models.User | None = db.query(models.User).filter(models.User.dni == user.dni).first()
    
    # If user dni is not registred
    if db_user_dni is None:
        # Add user dni to `users` table 
        db_user = models.User(dni=user.dni)
        db.add(db_user)
        db.commit()

        # Add user info to `active_users` table
        db_active_user = models.ActiveUser(dni=user.dni, username=user.username,
                                           password=hashed_password, kind=user.kind)
    
        db.add(db_active_user)
        db.commit()

        return db_active_user

    # If user dni exists and is currently active, raise error
    if db_user_dni.is_active:
        raise HTTPException(status.HTTP_409_CONFLICT, '¡DNI del usuario actualmente usado!')

    # otherwise, delete the register of inactive users for that user and add him to active ones
    
    # Set the current status to an active user
    db_user_dni.is_active = True
    db.commit()
    db.refresh(db_user_dni)

    # Delete the inactive register for the user by his dni
    db_inactive_user = db.query(models.InactiveUser).filter(models.InactiveUser.dni == user.dni).first()
    db.delete(db_inactive_user)
    db.commit()

    # Create and add a new register for the user
    db_new_user = models.ActiveUser(dni=user.dni, username=user.username, 
                                    password=hashed_password, kind=user.kind)
    db.add(db_new_user)
    db.commit()

    return db_new_user


def update_user(db: Session, username: str, updated_user: schemas.User) -> models.ActiveUser:
    """
    Updates the information of an existing user in the active users table.

    Args:
        db (Session): The database session used to query and modify the database.
        username (str): The username of the user to be updated.
        updated_user (schemas.User): The updated user data, including username,
            password, and kind.

    Returns:
        models.ActiveUser: The updated user record.

    Raises:
        HTTPException: If the user is not found or if the updated username
            is already registered.
    """
    user_db = get_user(db, username)
    if user_db is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, '¡Usuario no encontrado!')

    if username != updated_user.username and get_user(db, updated_user.username) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, '¡Usuario ya registrado!')
    
    user_db.username = updated_user.username
    user_db.password = get_password_hash(updated_user.password)
    user_db.kind = updated_user.kind

    db.commit()
    db.refresh(user_db)
    return user_db


def delete_user(db: Session, username: str) -> models.ActiveUser:
    """
    Deletes an existing user by moving them to the inactive users table and
    updating their status in the users table.

    Args:
        db (Session): The database session used to query and modify the database.
        username (str): The username of the user to be deleted.

    Returns:
        models.ActiveUser: The user record that was deleted.

    Raises:
        HTTPException: If the user is not found in the active users table.
    """
    # Retrieve the user from the active users table
    user_db: models.ActiveUser | None = get_user(db, username)
    if user_db is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, '¡Usuario no encontrado!')
    
    # Move the user record to the inactive users table
    db_inactive_user: models.InactiveUser = models.InactiveUser(dni=user_db.dni, username=user_db.username,
                                           password=user_db.password, kind=user_db.kind)
    db.add(db_inactive_user)
    db.commit()

    # Delete the user record from the active users table
    db.delete(user_db)
    db.commit()

    # Update the user's status to inactive in the users table
    db_user_dni: models.User | None = db.query(models.User).filter(models.User.dni == user_db.dni).first()
    db_user_dni.is_active = False

    db.commit()
    db.refresh(db_user_dni)

    return user_db


if __name__ == '__main__':
    from database import SessionLocal

    db = SessionLocal()
    user_db = get_user(db, 'admin1')
    print(None if user_db is None else user_db.__dict__)
    print(verify_password('password2', user_db.password))

    # create_user(db, schemas.User(dni=0, username='admin1', kind='admin', password='password'))
