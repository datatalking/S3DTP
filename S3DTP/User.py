# OS Stuff
import os

class User:
    def __init__(self, username="", password="", access=0, path=""):
        if (path == ""):
            path = os.getcwdb()
        else:
            path = bytes(path, "utf-8")
        self._level = access
        self._user = username
        self._password = password
        self._path = path
