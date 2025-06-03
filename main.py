# uvicorn main:app --reload

from fastapi import FastAPI, HTTPException, Depends, Form, Cookie, Request, Response, Path
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, HTMLResponse
from starlette import status
from sqlalchemy.orm import Session
from typing import Annotated, Optional
import logging
from jose import jwt, JWTError
from datetime import datetime, timedelta
from sqlalchemy import func
from db.database import engine, Base, get_db, db, SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, pwd_context
from db.models import UserModel, BookModel
from db.schemas import User, Book, BookToDelete
app = FastAPI(title="Менеджер бібліотеки книг")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")
logging.basicConfig(level=logging.INFO)

def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user_from_cookie(request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=401, detail="Не авторизований", headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Не авторизований")
    except JWTError:
        raise HTTPException(status_code=401, detail="Не авторизований")

    user = db.query(UserModel).filter(UserModel.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="Не авторизований")
    return user

@app.get("/")
def root():
    return RedirectResponse(url="/login")

@app.post("/token")
def login_for_access_token(
    response: Response,
    username: Annotated[str, Form()],
    password: Annotated[str, Form()],
    author: Annotated[str, Form()],
    db: Session = Depends(get_db)
):
    user = db.query(UserModel).filter(UserModel.username == username).first()

    try:
        if not user:
            return RedirectResponse(url="/login?msg=Невірні%20дані", status_code=status.HTTP_303_SEE_OTHER)

        if not pwd_context.verify(password, user.password):
            return RedirectResponse(url="/login?msg=Невірні%20дані", status_code=status.HTTP_303_SEE_OTHER)

        if user.author != author:
            return RedirectResponse(url="/login?msg=Автор%20не%20співпадає", status_code=status.HTTP_303_SEE_OTHER)

    except Exception as e:
        logging.error(f"Помилка перевірки паролю або автора: {e}")
        return RedirectResponse(url="/login?msg=Помилка%20перевірки", status_code=status.HTTP_303_SEE_OTHER)

    access_token = create_access_token(data={"sub": user.username})
    redirect_response = RedirectResponse(url=f"/menu/{author}", status_code=status.HTTP_303_SEE_OTHER)
    redirect_response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax"
    )
    return redirect_response

@app.get("/login")
def login(
    request: Request,
    msg: Optional[str] = None,
    access_token: Optional[str] = Cookie(default=None),
    db: Session = Depends(get_db)
):
    if access_token:
        try:
            payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str = payload.get("sub")
            if username:
                user = db.query(UserModel).filter(UserModel.username == username).first()
                if user:
                    return RedirectResponse(f"/menu/{user.username}", status_code=303)
            msg = "Не знайдено користувача"
        except JWTError:
            msg = "Невірний токен"
    return templates.TemplateResponse("login.html", {"request": request, "title": "Вхід", "msg": msg})


@app.get("/register")
def register_form(request: Request, msg: Optional[str] = None):
    return templates.TemplateResponse("register.html", {"request": request, "title": "Реєстрація", "msg": msg})

@app.post("/register")
def register_user(
    request: Request,
    author: str = Form(),
    username: str = Form(),
    password: str = Form(),
    client_id: str = Form(None),
    client_secret: str = Form(None),
    db: Session = Depends(get_db)
):
    existing_user = db.query(UserModel).filter(UserModel.username == username).first()
    if existing_user:
        return RedirectResponse(
            url=f"/register?msg=Користувач%20'{username}'%20вже%20існує",
            status_code=status.HTTP_303_SEE_OTHER
        )

    hashed_password = pwd_context.hash(password)

    new_user = UserModel(
        username=username,
        password=hashed_password,
        raw_password=password,
        author=author,
        client_id=client_id,
        client_secret=client_secret
    )

    try:
        db.add(new_user)
        db.commit()
    except Exception as e:
        db.rollback()
        logging.error(f"Помилка при створенні користувача: {e}")
        return RedirectResponse(
            url="/register?msg=Помилка%20реєстрації",
            status_code=status.HTTP_303_SEE_OTHER
        )

    return RedirectResponse(
        url="/login?msg=Користувача%20успішно%20створено",
        status_code=status.HTTP_303_SEE_OTHER
    )

@app.get("/register-delete")
def register_delete(request: Request, msg: str | None = None):
    return templates.TemplateResponse("register-delete.html", {"request": request, "title": "Видалення акаунта", "msg": msg})

@app.post("/register-delete")
def delete_user_form(
    username: str = Form(...),
    password: str = Form(...),
    db: Session = Depends(get_db)
):
    user = db.query(UserModel).filter(UserModel.username == username).first()
    if not user or not pwd_context.verify(password, user.password):
        return RedirectResponse(
            url="/register-delete?msg=Акаунт%20не%20знайдено",
            status_code=status.HTTP_303_SEE_OTHER
        )

    try:
        db.delete(user)
        db.commit()
    except Exception as e:
        db.rollback()
        logging.error(f"Помилка при видаленні користувача: {e}")
        return RedirectResponse(
            url="/register-delete?msg=Помилка%20видалення",
            status_code=status.HTTP_303_SEE_OTHER
        )

    return RedirectResponse(
        url="/login?msg=Акаунт%20успішно%20видалено",
        status_code=status.HTTP_303_SEE_OTHER
    )

templates = Jinja2Templates(directory="templates")

@app.get("/menu/{author}")
def menu(author: str, request: Request, current_user: UserModel = Depends(get_current_user_from_cookie)):
    is_admin = current_user.username.strip().lower() == "admin"
    return templates.TemplateResponse("menu.html", {
        "request": request,
        "title": "Меню",
        "user": current_user.username,
        "author": author,
        "is_admin": is_admin
    })

@app.get("/setting-user/{author}")
def setting_user(author: str, request: Request, current_user: UserModel = Depends(get_current_user_from_cookie)):
    return templates.TemplateResponse("setting-user.html", {"request": request, "title": "Налаштування користувача", "user": current_user.username, "author": author})

@app.get("/logout")
def logout():
    response = RedirectResponse(url="/login", status_code=302)
    response.delete_cookie(key="access_token")
    return response

@app.get("/change-name/{author}")
def get_change_name_form(author: str, request: Request, current_user: UserModel = Depends(get_current_user_from_cookie)):
    return templates.TemplateResponse("change-name.html", {
        "request": request,
        "title": "Змінити налаштування користувача",
        "user": current_user.username,
        "author": author
    })

@app.post("/change-name/{author}")
def post_change_name(
    request: Request,
    new_user: str = Form(),
    new_password: str = Form(),
    new_author: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user_from_cookie)
):
    db_user = db.query(UserModel).filter(UserModel.id == current_user.id).first()

    if not db_user:
        return templates.TemplateResponse("change-name.html", {
            "request": request,
            "title": "Змінити налаштування користувача",
            "user": current_user.username,
            "error": "Користувача не знайдено.",
            "author": current_user.author
        })

    existing_user = db.query(UserModel).filter(UserModel.username == new_user).first()
    if existing_user and existing_user.id != current_user.id:
        return templates.TemplateResponse("change-name.html", {
            "request": request,
            "title": "Змінити налаштування користувача",
            "user": current_user.username,
            "error": "Ім'я користувача вже зайнято.",
            "author": current_user.author
        })

    # обновляем данные
    if new_author:
        db_user.author = new_author
    db_user.username = new_user
    db_user.password = pwd_context.hash(new_password)
    db_user.raw_password = new_password

    db.commit()

    # Создаем новый токен для обновленного пользователя
    access_token = create_access_token(data={"sub": db_user.username})

    response = RedirectResponse(url=f"/setting-user/{db_user.author}", status_code=status.HTTP_303_SEE_OTHER)
    # Устанавливаем cookie с новым токеном
    response.set_cookie(key="access_token", value=access_token, httponly=True)

    return response

@app.get("/data-user/{author}")
def data_user(author: str, request: Request, current_user: UserModel = Depends(get_current_user_from_cookie)):
    return templates.TemplateResponse("data-user.html", {
        "request": request,
        "title": "Налаштування користувача",
        "author": author,
        "user": current_user.username,
        "password": current_user.raw_password
    })

@app.get("/delete-register/{author}")
def delete_register_get(request: Request, author: str, msg: Optional[str] = None):
    return templates.TemplateResponse("delete-register.html", {
        "request": request,
        "title": "Видалення акаунта",
        "username": author,
        "msg": msg
    })


@app.post("/delete-register/{author}")
def delete_register_post(author: str, db: Session = Depends(get_db)):
    user = db.query(UserModel).filter(UserModel.username == author).first()
    if not user:
        return RedirectResponse(f"/delete-register/{author}?msg=Користувача не знайдено", status_code=status.HTTP_303_SEE_OTHER)

    db.delete(user)
    db.commit()
    return RedirectResponse("/login", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/create-book/{author}")
def create_book_page(
    request: Request,
    author: str = Path(),
    current_user: UserModel = Depends(get_current_user_from_cookie)
):
    return templates.TemplateResponse("create-book.html", {
        "request": request,
        "title": "Створити книгу",
        "author": author
    })

@app.post("/create-book/{author}")
def create_book_form(
    request: Request,
    author: str = Path(),
    title: str = Form(),
    pages: int = Form(),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user_from_cookie)
):
    if author != current_user.author:
        return RedirectResponse("/login", status_code=303)
    existing = db.query(BookModel).filter(
        BookModel.title == title,
        BookModel.author == author
    ).first()
    if existing:
        return templates.TemplateResponse("create-book.html", {
            "request": request,
            "title": "Створити книгу",
            "author": author,
            "msg": "Книга вже існує"
        })
    new_book = BookModel(author=author, title=title, pages=pages)
    db.add(new_book)
    db.commit()
    return RedirectResponse(f"/menu/{author}", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/update-book/{author}")
def update_book(author: str, request: Request):
    return templates.TemplateResponse("update-book.html", {
        "request": request, 
        "title": "Оновити книгу",
        "author": author
    })


@app.post("/update-book/{author}")
def update_book_form(
    author: str,
    request: Request,
    old_title: str = Form(),
    new_title: str = Form(),
    new_pages: int = Form(),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user_from_cookie)
):
    book = db.query(BookModel).filter_by(
        title=old_title,
    ).first()

    if not book:
        return {"error": "Book not found"}
    book.title = new_title
    book.pages = new_pages
    db.commit()

    return RedirectResponse(f"/menu/{author}", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/delete-book/{author}")
def delete_book_page(author: str, request: Request, msg: Optional[str] = None):
    return templates.TemplateResponse("delete-book.html", {
        "request": request,
        "title": "Видалити книгу",
        "msg": msg,
        "author": author
    })

@app.post("/delete-book/{author}")
def delete_book_form(
    author: str,
    request: Request,
    title: str = Form(...),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user_from_cookie)
):
    if author != current_user.username:
        return RedirectResponse("/login", status_code=303)

    book = db.query(BookModel).filter(
        func.lower(BookModel.author) == author.lower(),
        func.lower(BookModel.title) == title.lower()
    ).first()

    if not book:
        return templates.TemplateResponse("delete-book.html", {
            "request": request,
            "title": "Видалити книгу",
            "msg": "Книгу не знайдено",
            "author": author
        })

    db.delete(book)
    db.commit()
    
    return RedirectResponse(f"/menu/{author}", status_code=status.HTTP_303_SEE_OTHER)

@app.post("/books/{author}")
def create_book(book: Book, db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user_from_cookie)):
    existing = db.query(BookModel).filter(BookModel.title == book.title, BookModel.author == book.author).first()
    if existing:
        raise HTTPException(status_code=400, detail="Книга вже існує")

    new_book = BookModel(title=book.title, author=book.author, pages=book.pages)
    db.add(new_book)
    db.commit()
    return {"message": "Книгу додано"}

@app.put("/books/")
def update_book(book: Book, db: Session = Depends(get_db), current_user: UserModel = Depends(get_current_user_from_cookie)):
    book_db = db.query(BookModel).filter(BookModel.title == book.title, BookModel.author == book.author).first()
    if not book_db:
        raise HTTPException(status_code=404, detail="Книгу не знайдено")

    book_db.pages = book.pages
    db.commit()
    return {"message": "Книгу оновлено"}

@app.get("/get-books/{author}")
def get_books_page(request: Request, author: str = "", db: Session = Depends(get_db)):
    books = None
    if author:
        books = db.query(BookModel).filter(BookModel.author.ilike(f"%{author}%")).all()
    return templates.TemplateResponse("get-books.html", {
        "request": request,
        "title": "Знайти книги",
        "books": books,
        "author": author
    })

@app.get("/books/{author}", response_class=HTMLResponse)
def get_books_by_author(author: str, request: Request, db: Session = Depends(get_db)):
    books = db.query(BookModel).filter(BookModel.author == author).all()
    return templates.TemplateResponse("books-author.html", {
        "request": request,
        "title": f"Книги автора {author}",
        "author": author,
        "books": books
    })

# Панель админа
@app.get("/admin-error", response_class=HTMLResponse)
def admin_error_get(request: Request, current_user: UserModel = Depends(get_current_user_from_cookie)):
    if current_user.username.strip().lower() != "admin":
        return templates.TemplateResponse("admin-error.html", {
            "request": request,
            "author": current_user.username,
            "title": "Помилка доступу",
            "user": current_user.username,
            "msg": "Вибачте, але ця функція доступна лише для адміністратора."
            
        })
    return RedirectResponse(url="/admin", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/admin")
def admin_panel(request: Request, current_user: UserModel = Depends(get_current_user_from_cookie)):
    if current_user.username.strip().lower() != "admin":
        return RedirectResponse(url="/admin-error")
    
    return templates.TemplateResponse("admin.html", {
        "request": request,
        "title": "Адмін панель",
        "user": current_user.username,
        "author": current_user.username
    })

@app.get("/admin-create-book")
def create_book_get(request: Request, msg: str | None = None, current_user: UserModel = Depends(get_current_user_from_cookie)):
    if current_user.username.strip().lower() != "admin":
        return RedirectResponse(url="/admin-error")
    
    return templates.TemplateResponse("admin-create-book.html", {
        "request": request,
        "title": "Створення книги",
        "msg": msg
    })

@app.post("/admin-create-book")
def create_book_post(
    request: Request,
    title: str = Form(),
    author: str = Form(),
    pages: int = Form(),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user_from_cookie)
):
    existing = db.query(BookModel).filter(
        func.lower(BookModel.title) == title.strip().lower(),
        func.lower(BookModel.author) == author.strip().lower()
    ).first()
    if existing:
        return templates.TemplateResponse("admin-create-book.html", {
            "request": request,
            "title": "Створити книгу",
            "msg": "Книга вже існує"
        })

    new_book = BookModel(title=title.strip(), author=author.strip(), pages=pages)
    db.add(new_book)
    db.commit()
    return RedirectResponse("/admin", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/admin-update-book")
def update_book_get(request: Request, msg: str | None = None, current_user: UserModel = Depends(get_current_user_from_cookie)):
    if current_user.username.strip().lower() != "admin":
        return RedirectResponse(url="/admin-error")
    
    return templates.TemplateResponse("admin-update-book.html", {
        "request": request,
        "title": "Оновлення книги",
        "msg": msg
    })

@app.post("/admin-update-book")
def update_book_post(
    request: Request,
    old_author: str = Form(),
    old_title: str = Form(),
    new_author: str = Form(),
    new_title: str = Form(),
    new_pages: int = Form(),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user_from_cookie)
):
    book_db = db.query(BookModel).filter(
        func.lower(BookModel.author) == old_author.strip().lower(),
        func.lower(BookModel.title) == old_title.strip().lower()
    ).first()

    if not book_db:
        return templates.TemplateResponse("admin-update-book.html", {
            "request": request,
            "title": "Оновити книгу",
            "msg": "Стара книга не знайдена"
        })

    book_db.author = new_author.strip()
    book_db.title = new_title.strip()
    book_db.pages = new_pages
    db.commit()

    return RedirectResponse("/admin", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/admin-delete-book")
def delete_book_get(request: Request, msg: str | None = None, current_user: UserModel = Depends(get_current_user_from_cookie)):
    if current_user.username.strip().lower() != "admin":
        return RedirectResponse(url="/admin-error")
    
    return templates.TemplateResponse("admin-delete-book.html", {
        "request": request,
        "title": "Видалення книги",
        "msg": msg
    })

@app.post("/admin-delete-book")
def delete_book_post(
    request: Request,
    author: str = Form(),
    title: str = Form(),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user_from_cookie)
):
    book = db.query(BookModel).filter(
        func.lower(BookModel.author) == author.strip().lower(),
        func.lower(BookModel.title) == title.strip().lower()
    ).first()

    if not book:
        return templates.TemplateResponse("admin-delete-book.html", {
            "request": request,
            "title": "Видалити книгу",
            "msg": "Книгу не знайдено"
        })

    db.delete(book)
    db.commit()
    return RedirectResponse("/admin", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/admin-register-delete")
def user_delete_get(
    request: Request,
    db: Session = Depends(get_db),
    msg: str | None = None,
    current_user: UserModel = Depends(get_current_user_from_cookie)
):
    if current_user.username.strip().lower() != "admin":
        return RedirectResponse(url="/admin-error")
    users = db.query(UserModel).all()
    return templates.TemplateResponse("admin-register-delete.html", {
        "request": request,
        "title": "Видалення Користувача",
        "msg": msg,
        "users": users
    })

@app.post("/admin-register-delete")
def user_delete_post(
    request: Request,
    username: str = Form(),
    db: Session = Depends(get_db),
    current_user: UserModel = Depends(get_current_user_from_cookie)
):
    user = db.query(UserModel).filter(func.lower(UserModel.username) == username.strip().lower()).first()
    if not user:
        return templates.TemplateResponse("admin-register-delete.html", {
            "request": request,
            "title": "Видалення Користувача",
            "msg": f"Користувача {username} не знайдено",
            "users": db.query(UserModel).all()
        })

    db.delete(user)
    db.commit()
    return RedirectResponse("/admin-register-delete", status_code=status.HTTP_303_SEE_OTHER)