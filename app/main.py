import os
from datetime import datetime, timedelta
from typing import List, Optional

import jwt
import sqlalchemy as sa
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from pydantic import BaseModel
from sqlmodel import Field, Relationship, Session, SQLModel, create_engine, select

# JWT
SECRET_KEY = "change-this-to-a-long-random-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# password hash
pwd_hasher = PasswordHash.recommended()


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


# DB
DATABASE_URL = os.environ["DATABASE_URL"]
engine = create_engine(DATABASE_URL, echo=True)


fake_users_db = {
    "hugin": {
        "username": "hugin",
        "full_name": "Kaho Chan",
        "email": "hugin@example.com",
        "hashed_password": pwd_hasher.hash("secret"),
        "disabled": False,
    }
}


# model
# User
class UserBase(SQLModel):
    username: str
    email: str


class User(UserBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    items: List["Item"] = Relationship(back_populates="owner")


class UserCreate(UserBase):
    pass


class UserRead(UserBase):
    id: int


# Item
class ItemBase(SQLModel):
    name: str
    description: Optional[str] = None


class Item(ItemBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    user_id: int | None = Field(default=None, foreign_key="user.id")
    owner: Optional[User] = Relationship(back_populates="items")


class ItemCreate(ItemBase):
    user_id: int


class ItemRead(ItemBase):
    id: int
    user_id: int


class ItemUpdate(SQLModel):
    name: Optional[str] = None
    description: Optional[str] = None


# For get user with item
class UserReadWithItems(UserBase):
    id: int
    items: List[ItemRead] = []


# setting up FastAPI
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Vite の開発URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session


@app.get("/")
def root():
    return {"status": "ok"}


# User CRUD
@app.post("/users/", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(payload: UserCreate, session: Session = Depends(get_session)):
    user = User.model_validate(payload)
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


@app.get("/users/{user_id}", response_model=UserReadWithItems)
def get_user(user_id: int, session: Session = Depends(get_session)):
    user = session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.get("/users/", response_model=List[UserRead])
def list_users(session: Session = Depends(get_session)):
    return session.exec(select(User)).all()


# item CRUD
@app.post("/items/", response_model=ItemRead, status_code=status.HTTP_201_CREATED)
def create_item(payload: ItemCreate, session: Session = Depends(get_session)):
    # user_id が存在するかチェック
    user = session.get(User, payload.user_id)
    if not user:
        raise HTTPException(status_code=400, detail="User does not exist")
    item = Item.model_validate(payload)
    session.add(item)
    session.commit()
    session.refresh(item)
    return item


@app.get("/items/", response_model=List[ItemRead])
def list_items(
    limit: int = Query(10, ge=1, le=100),
    offset: int = Query(0, ge=0),
    q: str = "",
    session: Session = Depends(get_session),
):
    stmt = select(Item)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(sa.or_(Item.name.ilike(like), Item.description.ilike(like)))
    stmt = stmt.offset(offset).limit(limit)
    return session.exec(stmt).all()


@app.get("/items/{item_id}", response_model=ItemRead)
def get_item(item_id: int, session: Session = Depends(get_session)):
    item = session.get(Item, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    return item


@app.put("/items/{item_id}", response_model=ItemRead)
def put_item(
    item_id: int, payload: ItemCreate, session: Session = Depends(get_session)
):
    item = session.get(Item, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    item.name = payload.name
    item.description = payload.description
    item.user_id = payload.user_id
    session.add(item)
    session.commit()
    session.refresh(item)
    return item


@app.patch("/items/{item_id}", response_model=ItemRead)
def patch_item(
    item_id: int, payload: ItemUpdate, session: Session = Depends(get_session)
):
    item = session.get(Item, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    data = payload.model_dump(exclude_unset=True)
    for k, v in data.items():
        setattr(item, k, v)
    session.add(item)
    session.commit()
    session.refresh(item)
    return item


@app.delete("/items/{item_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_item(item_id: int, session: Session = Depends(get_session)):
    item = session.get(Item, item_id)
    if not item:
        raise HTTPException(status_code=404, detail="Item not found")
    session.delete(item)
    session.commit()
    return None


# For login
class AuthUser(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None


class AuthUserInDB(AuthUser):
    hashed_password: str


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_hasher.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_hasher.hash(password)


def get_auth_user(db, username: str) -> Optional[AuthUserInDB]:
    if username in db:
        return AuthUserInDB(**db[username])
    return None


def authenticate_user(db, username: str, password: str) -> Optional[AuthUserInDB]:
    user = get_auth_user(db, username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    data をペイロードにして JWT を発行
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode["exp"] = expire
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# OAuth2 の "password" フロー & Bearer トークンを宣言:contentReference[oaicite:4]{index=4}
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
):
    """
    username / password を受け取り、PyJWT で access_token を返す
    """
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        # OAuth2 仕様通り 401 + WWW-Authenticate を返す:contentReference[oaicite:5]{index=5}
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires,
    )
    return {"access_token": access_token, "token_type": "bearer"}


async def get_current_user(token: str = Depends(oauth2_scheme)) -> AuthUser:
    """
    Authorization: Bearer <JWT> を受け取って検証し、ユーザーを返す
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except (InvalidTokenError, KeyError, TypeError):
        # トークン不正・期限切れなど
        raise credentials_exception

    user = get_auth_user(fake_users_db, token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: AuthUser = Depends(get_current_user),
) -> AuthUser:
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.get("/auth/me", response_model=AuthUser)
async def read_auth_me(current_user: AuthUser = Depends(get_current_active_user)):
    return current_user
