from sqlalchemy import Column, String, Integer, Boolean, ForeignKey
from sqlalchemy.orm import relationship

from database import Base


class User(Base):
    """
    Represents a user in the system.

    Attributes:
        dni (int): The primary key, representing the user's identification number.
        is_active (bool): Indicates whether the user is active. Defaults to True.

    Relationships:
        active_user (ActiveUser): The related active user record.
        inactive_user (InactiveUser): The related inactive user record.
    """
    __tablename__ = "users"

    dni = Column(Integer, primary_key=True)
    is_active = Column(Boolean, nullable=False, default=True)

    active_user = relationship("ActiveUser", uselist=False, back_populates="user", passive_deletes=True)
    inactive_user = relationship("InactiveUser", uselist=False, back_populates="user", passive_deletes=True)


class ActiveUser(Base):
    """
    Represents an active user with specific credentials.

    Attributes:
        dni (int): The primary key, representing the user's identification number.
        username (str): The username of the active user. Must be unique.
        password (str): The password of the active user.
        kind (str): The type or role of the active user.

    Relationships:
        user (User): The related user record.
    """
    __tablename__ = "active_users"

    dni = Column(Integer, ForeignKey("users.dni"), primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    kind = Column(String, nullable=False)

    user = relationship("User", uselist=False, back_populates="active_user")


class InactiveUser(Base):
    """
    Represents an inactive user with specific credentials.

    Attributes:
        dni (int): The primary key, representing the user's identification number.
        username (str): The username of the inactive user. Must be unique.
        password (str): The password of the inactive user.
        kind (str): The type or role of the inactive user.

    Relationships:
        user (User): The related user record.
    """
    __tablename__ = "inactive_users"

    dni = Column(Integer, ForeignKey("users.dni"), primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    kind = Column(String, nullable=False)

    user = relationship("User", uselist=False, back_populates="inactive_user")
