build:
	docker compose build web

dev:
	docker compose run -p 8080:80 --rm --build web python -m fastapi dev --port 80 --host 0.0.0.0

serve:
	docker compose up web

test:
	docker compose run --rm -e PYTHONPATH=/code/app web python -m pytest

stop:
	docker compose stop