"""`buglupa connect`: let BugLupa Cloud's scanner test an app on your computer through a private tunnel.

The client opens one outbound, encrypted WebSocket to BugLupa's tunnel service and never listens for connections.
Requests arrive over that connection, and the client forwards each one only to the address you named (for example
`localhost:3000`). Standard library only.
"""

__version__ = "0.1.0"
