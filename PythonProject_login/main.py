from fastapi import FastAPI, Depends, HTTPException, status, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from passlib.context import CryptContext
from pydantic import BaseModel
from jose import jwt , JWTError
from datetime import datetime, timedelta,timezone
from typing import Optional,Annotated
from fastapi.staticfiles import StaticFiles


SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30


fake_users_db = {
    "user1": {
        "username": "user1",
        "password": "password123" ,
        "hashed_password": "hash",
        "disabled": False,
    }

}

class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None

class User(BaseModel):
    username: str
    password: str | None = None
    disabled: bool | None = None

class UserInDB(User):
    hashed_password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)

    def authenticate_user(fake_db, username: str, password: str):
        user = get_user(fake_users_db, username)
        if not user:
            return False
        if not verify_password(password, user.hashed_password):
            return False
        return user


templates = Jinja2Templates(directory="templates")


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=5)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except InvalidTokenError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)],
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


def get_jwt_from_cookie(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token is missing or invalid"
        )
    return token



def authenticate_user(fake_users_db, username, password):
    pass


@app.post("/login", response_class=RedirectResponse)
async def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
) -> Token:
    user_db = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user_db.username}, expires_delta=access_token_expires
    )
    return Token(access_token=access_token, token_type="bearer")


    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        secure=True,
    )


    return RedirectResponse(url="/protected", status_code=status.HTTP_303_SEE_OTHER)


@app.get("/", response_class=HTMLResponse)
async def login_form(request: Request):
    return templates.TemplateResponse("login_form.html", {"request": request})


@app.get("/protected", response_class=HTMLResponse)
async def protected_route(request: Request, token: str = Depends(get_jwt_from_cookie)):
    try:

        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return templates.TemplateResponse("protected.html", {"request": request, "username": payload['sub']})
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token is invalid"
        )


@app.post("/logout")
async def logout(response: Response):
    response.delete_cookie("access_token")
    return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

