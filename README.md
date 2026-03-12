# rendycrm-bk

Минимальный backend на Gin для отдельного деплоя.

## Endpoints

- `GET /health`
- `POST /auth/login`
- `GET /auth/me` (Bearer token)
- `POST /webhooks/telegram/client/:workspace/:secret`
- `POST /webhooks/telegram/operator`

## Local run

```bash
cp .env.example .env
go mod tidy
go run ./main.go
```

## Docker

```bash
docker build -t rendycrm-bk .
docker run --rm -p 3000:3000 --env-file .env rendycrm-bk
```

## CORS

- `CORS_ALLOWED_ORIGINS=*` — разрешить все origin.
- Поддерживаются маски вида `https://*.twc1.net`.
- Для cookie-сценария включите `CORS_ALLOW_CREDENTIALS=true` и задайте точные origin.
