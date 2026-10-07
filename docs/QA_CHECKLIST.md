# Manual QA checklist (run before tagging a release)

Automated tests can't open your real mailbox. This checklist covers what they can't.
Use a throwaway or low-stakes mailbox first. Heron only reads mail, but test with
something you can afford to look at closely.

## 0. Health check

```
python -m heron.doctor
```

Expect no FAIL lines. WARN lines on a brand-new install (no database or keys yet) are fine.

## 1. Start

```
uvicorn heron.api.app:create_app --factory          # terminal 1
streamlit run src/heron/ui/app.py                   # terminal 2
```

- [ ] `python -m heron.doctor --api-url http://127.0.0.1:8000` shows API PASS.
- [ ] The Streamlit page opens at http://localhost:8501 and asks for a token.
- [ ] A wrong token is refused; the token in `data/api_token` signs you in.
- [ ] Sign out returns to the login page.

## 2. Add a mailbox

- [ ] Add mailbox, enter your address: the provider is suggested and the server fills in.
- [ ] Save is greyed out until Test connection succeeds.
- [ ] A deliberately wrong password shows a readable error, not a stack trace.
- [ ] The right app password passes; Save adds it under Mailboxes.
- [ ] Changing one character of the password after a test disables Save again.

## 3. Fetch and analyse

- [ ] Fetch mail, Today, Fetch missing mail: progress moves and finishes.
- [ ] Click it again: "Everything in this range is already stored."
- [ ] Choose Yesterday: it fetches only that day.
- [ ] Dashboard: Emails matches roughly what your mailbox shows for today.
- [ ] Dashboard "Not yet checked" is 0 after a fetch finishes. If it isn't, the analysis hook in
      `worker/runner.py` isn't running (doctor reports this too).
- [ ] Your mail client still shows the same read/unread state as before: Heron never changes it.

## 4. Alerts

- [ ] Forward yourself a harmless test: a message from a free-mail address with a link whose
      text shows one site and goes to another. Fetch again; an alert should appear.
- [ ] Open the alert: reasons, evidence and the what-to-do list are readable.
- [ ] Acknowledge, Resolve, Reopen, Mark as false positive all work, and the counts change.
- [ ] A subject containing `![x](http://example.invalid/p.gif)` shows as literal text and loads nothing.

## 5. Restart safety

- [ ] Stop and restart both processes: mailboxes, mail and alert statuses are all still there.
- [ ] Fetch the same range again: nothing is downloaded twice.
- [ ] `python -m heron.doctor` shows no FAIL.

## 6. Before sharing the data folder or an image

- [ ] `data/` is in `.gitignore` and `git status` shows no secrets.
- [ ] `ls -l data/secret.key data/api_token` shows `-rw-------`.
