from fastapi import FastAPI, Depends, Query, HTTPException, status
from typing import Optional, List
import os
import sqlalchemy as sa
from sqlmodel import SQLModel, Field, create_engine, Session, select, Relationship
from fastapi.middleware.cors import CORSMiddleware


# DB
DATABASE_URL = os.environ["DATABASE_URL"]
engine = create_engine(DATABASE_URL, echo=True)

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

#For get user with item
class UserReadWithItems(UserBase):
    id: int
    items: List[ItemRead] = []

# setting up FastAPI
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Vite の開発URL
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
def put_item(item_id: int, payload: ItemCreate, session: Session = Depends(get_session)):
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
def patch_item(item_id: int, payload: ItemUpdate, session: Session = Depends(get_session)):
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

