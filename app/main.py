from typing import Union

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class Item(BaseModel):
    name: str
    price: float
    is_offer: Union[bool, None] = None


class UpdateItemResponse(BaseModel):
    item_id: int
    name: str

class ReadItemResponse(BaseModel):
    item_id: int
    q: str


@app.get("/")
def read_root():
    return { 'status': 'ok' }

@app.get("/items/{item_id}")
def read_item(item_id: int, q: Union[str, None] = None) -> ReadItemResponse:
    return { "item_id": item_id, "q": q }

@app.put("/items/{item_id}")
def update_item(item_id: int, item: Item) -> UpdateItemResponse:
    return { "name": item.name, "item_id": item_id }
