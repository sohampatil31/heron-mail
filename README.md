# Heron

Self-hosted phishing detection for your inbox.

> Work in progress. Not ready for use yet.

Heron connects to your mailboxes over IMAP (read-only), analyzes incoming
email for phishing signals, and shows a dashboard of verdicts, reasons, and
recommended actions. Everything runs on your own machine.

## Development

Requires Python 3.11+.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install

ruff check . && ruff format --check . && pytest
```

Commits follow [Conventional Commits](https://www.conventionalcommits.org)
(`feat:`, `fix:`, `test:`, `docs:`, `chore:`, `ci:`).

## Security

Never commit `.env`, `data/`, or real email. Test fixtures must be synthetic.
