# ShopEasy Lab Package

Two apps. Same store. One vulnerable, one fixed.

| | Vulnerable | Secure |
|---|---|---|
| URL | http://localhost:5000 | http://localhost:5001 |
| Folder | shopeasy-vulnerable/ | shopeasy-secure/ |

## Run both

```bash
cd shopeasy-combined
docker compose up --build -d
```

## Run one at a time

```bash
cd shopeasy-vulnerable && docker compose up --build -d
cd shopeasy-secure     && docker compose up --build -d
```

See shopeasy-combined/README.md for the full attack comparison guide.
