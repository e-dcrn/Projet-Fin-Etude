import os
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
HOME = os.path.join(os.path.dirname(__file__), "ftproot")
os.makedirs(HOME, exist_ok=True)
auth = DummyAuthorizer()
auth.add_user("duhan", "S3cr3tReel!", HOME, perm="elradfmw")  # vrai mdp (jamais deviné)
h = FTPHandler; h.authorizer = auth; h.banner = "IDS-Lab demo FTP ready"
FTPServer(("127.0.0.1", 2121), h).serve_forever()
