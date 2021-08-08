# 1.0.0
# ^^^^^ version

# Netwroking constants:
#   Server reply:
#       0: Ok
#       1: Operation not permitted
#       2: Operation failed
#       3: Memory operation failed, buffer over flow protection
#       4: Authentication problem
#       5: Snake bite, you have been banned (Future implementation)
#       6: Network transport error

from .Server import Server
from .Client import Client
from .User import User

__all__ = ["Server", "Client", "User"]

# Mode constants
READ = 0
WRITE = 1
RW = 2

# Location constants
FILE = 0
MEM = 1

# User constant
DEFAULT_USER = User()
