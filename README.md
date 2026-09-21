# Heron

Self-hosted phishing detection for your inbox.

> Work in progress. Not ready for use yet.

Heron connects to your mailboxes over IMAP (read-only), analyzes incoming
email for phishing signals, and shows a dashboard of verdicts, reasons, and
recommended actions. Everything runs on your own machine.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for how it is designed.

## Configuration

Settings come from environment variables or a `.env` file
(copy `.env.example` to get started).

| Variable | Default | Meaning |
|---|---|---|
| `HERON_DATA_DIR` | `./data` | Where the database and raw emails are stored |
| `HERON_TIMEZONE` | `UTC` | IANA timezone that decides what "today" means |

## Development

Requires Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install

ruff check . && ruff format --check . && pytest
```

Database migrations use Alembic: `alembic upgrade head` applies them, and
`alembic revision -m "describe the change"` creates a new one.

Commits follow [Conventional Commits](https://www.conventionalcommits.org)
(`feat:`, `fix:`, `test:`, `docs:`, `chore:`, `ci:`).

## Security

Never commit `.env`, `data/`, or real email. Test fixtures must be synthetic.
