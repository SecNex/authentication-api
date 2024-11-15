# SecNex Authentication API

## Development

1. Create a `.env` file based on `.env.example` and populate with your values.
2. Run `go run .` to start the server.

## Usage

### Login

To login, send a POST request to `/auth/login` with a JSON body containing the username and password.

```shell
curl -X POST http://localhost:8081/auth/login -H "Content-Type: application/json" -d '{"username": "testuser", "password": "password123"}'
```

### Refresh Token

To refresh the access token, send a POST request to `/auth/refresh` with a JSON body containing the refresh token.

```shell
curl -X POST http://localhost:8081/auth/refresh -H "Content-Type: application/json" -d '{"refresh_token": "your_refresh_token"}'
```

### Logout

To logout, send a POST request to `/auth/logout` with a JSON body containing the refresh token.

```shell
curl -X POST http://localhost:8081/auth/logout -H "Content-Type: application/json" -d '{"refresh_token": "your_refresh_token"}'
```
