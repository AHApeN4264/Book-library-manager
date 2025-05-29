# uvicorn main:app --reload

from fastapi import FastAPI, HTTPException, Depends, Form, Request
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from starlette import status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from typing import Annotated
import logging
from passlib.context import CryptContext
from jose import jwt, JWTError
from datetime import datetime, timedelta

from db.database import engine, Base, get_db
from db.models import UserModel, BookModel
from db.schemas import User, Book, BookToDelete

# ---------- Ініціалізація ----------
app = FastAPI(title="Менеджер бібліотеки книг")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
logging.basicConfig(level=logging.INFO)

# ---------- JWT конфіг ----------
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=401,
        detail="Не вдалося перевірити токен",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(UserModel).filter(UserModel.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# ---------- Хешування паролів ----------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ---------- HTML сторінки ----------
@app.get("/")
def menu(request: Request):
    return templates.TemplateResponse("menu.html", {"request": request, "title": "Бібліотека"})

@app.get("/login")
def login(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "title": "Вхід"})

@app.get("/register")
def register(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "title": "Реєстрація"})

@app.get("/create-book")
def create_book_page(request: Request):
    return templates.TemplateResponse("create-book.html", {"request": request, "title": "Створити книгу"})

@app.get("/delete-book")
def delete_book_page(request: Request):
    return templates.TemplateResponse("delete-book.html", {"request": request, "title": "Видалити книгу"})

@app.get("/get-books")
def get_books_page(request: Request):
    return templates.TemplateResponse("get-books.html", {"request": request, "title": "Знайти книги"})

@app.get("/update-book")
def update_book_page(request: Request):
    return templates.TemplateResponse("update-book.html", {"request": request, "title": "Оновити книгу"})

# ---------- Реєстрація ----------
@app.post("/register")
def register_user(
    username: str = Form(...),
    password: str = Form(...),
    client_id: str = Form(None),
    client_secret: str = Form(None),
    db: Session = Depends(get_db)
):
    existing_user = db.query(UserModel).filter(UserModel.username == username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail=f"Користувач '{username}' вже існує")

    hashed_password = pwd_context.hash(password)
    new_user = UserModel(
        username=username,
        password=hashed_password,
        client_id=client_id,
        client_secret=client_secret
    )

    try:
        db.add(new_user)
        db.commit()
        return {"message": f"Користувача '{username}' зареєстровано успішно"}
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Помилка додавання користувача")
    except Exception as e:
        db.rollback()
        logging.error(f"Register user error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Внутрішня помилка сервера")

# ---------- Авторизація ----------
@app.post("/token")
def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    db: Session = Depends(get_db)
):
    user = db.query(UserModel).filter(UserModel.username == form_data.username).first()
    if not user or not pwd_context.verify(form_data.password, user.password):
        raise HTTPException(status_code=400, detail="Неправильний логін або пароль")

    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# ---------- Створити книгу через HTML-форму ----------
@app.post("/create-book")
def create_book_form(
    title: str = Form(...),
    author: str = Form(...),
    pages: int = Form(...),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user),
):
    existing = db.query(BookModel).filter(
        BookModel.title == title, BookModel.author == author
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Книга вже існує")

    new_book = BookModel(title=title, author=author, pages=pages)
    db.add(new_book)
    db.commit()
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)

# ---------- CRUD через API ----------
@app.post("/books/")
def create_book(book: Book, db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
    existing = db.query(BookModel).filter(
        BookModel.title == book.title, BookModel.author == book.author
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Книга вже існує")

    new_book = BookModel(title=book.title, author=book.author, pages=book.pages)
    db.add(new_book)
    db.commit()
    return {"message": "Книгу додано"}

@app.get("/books/{author}")
def get_books_by_author(author: str, db: Session = Depends(get_db)):
    books = db.query(BookModel).filter(BookModel.author == author).all()
    if not books:
        raise HTTPException(status_code=404, detail="Книги не знайдено")
    return {"author": author, "books": [{"title": b.title, "pages": b.pages} for b in books]}

@app.put("/books/")
def update_book(book: Book, db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
    book_db = db.query(BookModel).filter(
        BookModel.title == book.title, BookModel.author == book.author
    ).first()
    if not book_db:
        raise HTTPException(status_code=404, detail="Книгу не знайдено")

    book_db.pages = book.pages
    db.commit()
    return {"message": "Книгу оновлено"}

@app.delete("/books/")
def delete_book(book: BookToDelete, db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
    book_db = db.query(BookModel).filter(
        BookModel.title == book.title, BookModel.author == book.author
    ).first()
    if not book_db:
        raise HTTPException(status_code=404, detail="Книгу не знайдено")

    db.delete(book_db)
    db.commit()
    return {"message": "Книгу видалено"}

@app.delete("/register")
def delete_user(user: User, db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user)):
    user_db = db.query(UserModel).filter(UserModel.username == user.username).first()
    if not user_db:
        raise HTTPException(status_code=404, detail="Користувача не знайдено")

    db.delete(user_db)
    db.commit()
    return {"message": f"Користувача '{user.username}' видалено"}

# ---------- Створити таблиці ----------
Base.metadata.create_all(bind=engine)
