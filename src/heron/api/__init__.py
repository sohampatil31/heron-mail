"""The API: a FastAPI app that is the only thing the dashboard talks to.

Never connects to IMAP directly - it queries the vault and enqueues jobs
for the worker to pick up. See ARCHITECTURE.md.
"""
