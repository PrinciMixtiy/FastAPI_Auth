# FastAPI Authentication

## Endpoints

- **POST `/auth/register`**
   Create an user account.

- **POST `/auth/login`**  
   Authenticate the user and retrieve tokens.

- **POST `/auth/refresh`**  
   Use the refresh token to renew the access token.

- **GET `/auth/me`**  
   Get the current authenticated user.

## Example Workflow

1. Login with `/auth/login` to obtain tokens.
2. Include the `access_token` in the `Authorization` header (`Bearer <token>`).
3. Use `/auth/refresh` with request body `{"refresh_token": "..."}` when the access token expires.

## Swagger documentation

```sh
python -m pip install -r requirements.txt

fastapi dev main.py
```

Then go to `http://127.0.0.1:8000`.
