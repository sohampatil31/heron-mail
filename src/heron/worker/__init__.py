"""The worker: claims jobs from the database and runs them.

The API and the worker never call each other directly (see
ARCHITECTURE.md - "how the pieces talk"). The `jobs` table is the queue:
the API enqueues, the worker claims and executes.
"""
