# yo API

## Setup

```bash
# Compile project (development mode)
cargo build

# Compile and serve on default port :3000
cargo run -- --serve

# Serve with auto-reload
cargo watch -x 'run -- --serve'

# Production mode
cargo run --release -- --serve
```

The server will start at `http://127.0.0.1:3000`

## curl example commands

```sh
curl -X POST http://127.0.0.1:3000/api/register -H 'Content-Type: application/json' -d '{"username": "user1", "password": "password123"}'
# Response 200 OK, no body
```

```sh
curl -X POST http://127.0.0.1:3000/api/login -H 'Content-Type: application/json' -d '{"username": "user1", "password": "password123"}'
{"token":"722e1690-be68-4046-bd99-8df3ad192f9b"}
```

```sh
curl -X POST http://127.0.0.1:3000/api/connections/request -H 'Content-Type: application/json' -H 'Authorization: Bearer 722e1690-be68-4046-bd99-8df3ad192f9b' -d '{"username": "user2"}'
{}
```
