# buglupa-connect

Let BugLupa Cloud's scanner test an app running on your computer, through a private tunnel that only BugLupa's
scanner can use. Your app is never put on the internet.

```
$ pipx install buglupa-connect        # or: uvx buglupa-connect localhost:3000
$ export BUGLUPA_CONNECT_TOKEN=...    # a connect token for your project, from BugLupa Cloud
$ buglupa connect localhost:3000
```

- The client makes one outbound, encrypted connection to BugLupa and never listens for connections.
- It forwards requests only to the one address you name (local and private addresses only).
- Every connection needs a short-lived token from your BugLupa Cloud project; Ctrl+C ends access at once.
- Python 3.10 or newer, standard library only, so there is nothing else to audit.

BugLupa Cloud is in early access at [buglupa.com](https://buglupa.com). Documentation: https://buglupa.com/docs

This client is open source under the MIT licence so you can read exactly what runs on your computer. BugLupa itself
is a separate product by [Yarqat](https://yarqat.com). Security reports: support@yarqat.com.
