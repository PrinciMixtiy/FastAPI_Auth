# FastAPI Authentication

## To do

- Add `.env` file in project directory with variable `SECRET_KEY`.

```.dotenv
SECRET_KEY="your_secret_key"
```

- Install dependencies

```shell
python -m venv env
source env/bin/activate

python -m pip install -r requirements.txt
```

- Run database migrations

```shell
alembic upgrade head
```

- Run the application

```shell
cd app
# Make sure to be in app directory when running the app.
fastapi dev main.py
```

## Example Workflow

1. Create a user account `auth/register`.
2. Login with `/auth/login` to obtain tokens.
3. Include the `access_token` in the `Authorization` header (`Bearer <token>`).
4. Use `/auth/refresh` with request body `{"refresh_token": "..."}` when the access token expires.

## Swagger documentation

```sh
cd app
fastapi dev main.py
```

Then go to `http://127.0.0.1:8000/docs`.
