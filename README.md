# Запуск:
```
docker compose build
docker compose up
```

# Проверка:
```
curl --location 'localhost/get-tokens?user_id=123e4567-e89b-12d3-a456-426614174000'

curl --location 'localhost/refresh-token?user_id=123e4567-e89b-12d3-a456-426614174000' \
--header 'Content-Type: application/json' \
--data '{"access_token":"","refresh_token":""}'
```
