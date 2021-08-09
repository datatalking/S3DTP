# S3DTP
S3DTP is the Simple Secure Socket Data Transport Protocol.

Documentation:
```python
class User:

  # Makes new user
  def __init__(Optional: string username ("" by default), Optional: string password ("" by default (None)), Optional: int access (S3DTP.READ by default), Optional: string path ("" by default (working directory))):
    # Return type: None

class Server:

  # Starts server
  def __init__(string IP Address, Optional: bool encryption (True by default), Optional: int maxPeers (-1 by default (unlimited))):
    # Return type: None

  # Adds user to server
  def addUser(User user):
    # Return type: None
    # Raises exception if arg type is not of User type

  # Shuts down server
  def close():
    # Return type: None

class Client:
  # Connects/(re)connects to (the) same/a (different) server
  def __init__/__call__(string IP Address, Optional: string username ("" by default), Optional: string password ("" by default (None))):
    Return type: None

  # Reads data from file and sends it to the server
  def write_from_file(string filepath, Optional: int mode (S3DTP.FILE by default), Optional: string name ("" by default (Will use file name))):
    # Return type: bool (Indicates whether the operation was a success)

  # Reads data from buffer and sends it to the server
  def write_from_memory(bytes data, string filepath, Optional: int mode (S3DTP.FILE by default)):
    # Return type: bool (Indicates whether the operation was a success)

  # Reads from server
  def read(string name, Optional: string filepath ("" by default (See return type comment))):
    # Return type: bytes (If "filepath' is blank then it will return the data, otherwise it will return a blank byte string (0xFF will be returned upon error code from server))

  # Gets a list of files and directories
  def ls(Optional: int mode (Location in this context) (S3DTP.FILE by default), Optional: string filepath ("" by default (User root directory))):
    # Return type: list of byte strings as names

  # Deletes file, folder, or memory
  def rm(string path (or memory name):
    # Return type: bool (Indicates whether the operation was a success)

```

Both the client and server will have loggers for posting bugs/tracing problems. 
