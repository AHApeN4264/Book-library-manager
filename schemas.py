from pydantic import BaseModel, Field
from typing import Union
from pydantic import BaseModel, EmailStr
from typing import Optional

class User(BaseModel):
    username: str
    password: str
    client_id: Optional[str] = None  # теперь можно писать что угодно
    client_secret: Optional[str] = None


class Book(BaseModel):
    author: str = Field(..., min_length=3, max_length=30)
    title: str = Field(..., min_length=1)
    pages: int = Field(..., gt=10)

class BookToDelete(BaseModel):
    author: str
    title: str
