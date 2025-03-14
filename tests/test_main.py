from fastapi.testclient import TestClient

from main import app, Item

client = TestClient(app)

def test_read_root():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == { "status": "ok" }

def test_read_item():
    response = client.get("/items/1234?q=Hello")
    assert response.status_code == 200
    assert response.json() == {"item_id": 1234, "q": "Hello"}

def test_update_item():
    item = Item(name="New Item", price=9.99, is_offer=False)
    response = client.put("/items/5678", json=item.dict())
    assert response.status_code == 200
    assert response.json() == {"item_id": 5678, "name": item.name}
