# buglupa-connect

Let BugLupa Cloud's scanner test an app running on your computer, through a private tunnel that only BugLupa's
scanner can use.

```
$ pipx install buglupa-connect        # or: uvx buglupa-connect localhost:3000
$ export BUGLUPA_CONNECT_TOKEN=...    # a connect token for your project, from BugLupa
$ buglupa connect localhost:3000
```

The client makes one outbound, encrypted connection to BugLupa and never listens for connections. It forwards
requests only to the address you name (local and private addresses only), and Ctrl+C ends access at once.
Python 3.10 or newer; standard library only.

Documentation: https://buglupa.com/docs
