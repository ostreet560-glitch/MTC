# App-Auth Validator

This is a small test validator that responds to requests intended for `wq-test.AkiACG.com`.

How to run:

1. Ensure Python 3 is available.
2. Edit `dict.yml` to include your desired `RSA`, `RSA_K`, and `IV` values.
3. Run the server:

```powershell
python server.py
```

The server listens on port `3502` and will only accept requests whose `Host` header contains `wq-test.AkiACG.com`.

`dict.yml` supports simple key: value pairs and a `|` block for multiline PEM values.
