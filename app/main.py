from fastapi import FastAPI, Depends
from sqlmodel import SQLModel, Field, create_engine, Session, select
import os

# ====== DB 設定 ======
# docker-compose.yml の environment: DATABASE_URL=... から取得
DATABASE_URL = os.environ["DATABASE_URL"]

# SQLAlchemy/SQLModel エンジン作成
engine = create_engine(DATABASE_URL, echo=True)


# ====== モデル定義 ======
class Item(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    name: str
    description: str | None = None


# ====== FastAPI アプリ ======
app = FastAPI()

# サーバ起動時にテーブル作成
@app.on_event("startup")
def on_startup():
    SQLModel.metadata.create_all(engine)


# ====== DB セッション依存性 ======
def get_session():
    with Session(engine) as session:
        yield session


# ====== エンドポイント ======
@app.get("/")
def root():
    return {"status": "ok"}

@app.post("/items/")
def create_item(item: Item, session: Session = Depends(get_session)):
    session.add(item)
    session.commit()
    session.refresh(item)
    return item

@app.get("/items/")
def read_items(session: Session = Depends(get_session)):
    return session.exec(select(Item)).all()

