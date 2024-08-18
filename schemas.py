from pydantic import BaseModel


class User(BaseModel):
    """
    Represents the base model for a user.

    Attributes:
        dni (int): The user's identification number.
        username (str): The username of the user.
        kind (str): The type or role of the user.
        password (str): The user's password.
    """
    dni: int
    username: str
    kind: str
    password: str


class Token(BaseModel):
    """
    Represents an authentication token.

    Attributes:
        access_token (str): The token that grants access to the system.
        token_type (str): The type of the token, typically "Bearer".
    """
    access_token: str
    token_type: str


class TokenData(BaseModel):
    """
    Represents the data contained within a token.

    Attributes:
        username (str | None): The username extracted from the token.
            Can be None if the token does not contain a username.
    """
    username: str | None = None
