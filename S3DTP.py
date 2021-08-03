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

# Networking
import socket

# Compression
import blosc

# Encryption/Hash
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Hash import SHA3_256

# Concurrency/Async
import aiofile
import asyncio
import threading

# Memory Management
import psutil as ps

# Timing
import time

# Math
import math

# OS Stuff
import os

# Mode constants
READ = 0
WRITE = 1
RW = 2

class User:
    def __init__(self, username="", password="", access=READ, path=""):
        if (path == ""):
            path = os.getcwdb()
        else:
            path = bytes(path, "utf-8")
        self._level = access
        self._user = username
        self._password = password
        self._path = path

# Location constants
FILE = 0
MEM = 1

# User constant
DEFAULT_USER = User()


class Server:
    def __init__(self, iph="", encryption=True, maxPeers=-1):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((iph, 5500))
        if maxPeers < 1:
            self._sock.listen(1000000)
        else:
            self._sock.listen(1 + maxPeers)
        self._encrypt = encryption
        self._running = True
        self._max = maxPeers
        self._users = []
        self.memstorage = {}
        self.peers = 0
        if encryption:
            self._private = RSA.generate(2048)
            self._decryptor = PKCS1_OAEP.new(self._private)
            self._public = self._private.public_key()
        threading.Thread(target=self._manager).start()

    def _manager(self):
        if self._max < 1:
            while self._running:
                try:
                    client = self._sock.accept()
                    threading.Thread(target=self._peer, args=(client[0],)).start()
                except:
                    pass
        else:
            while self._running:
                while ((self._max == self.peers) & (self._running)):
                    time.sleep(0.01)
                if (self._running):
                    try:
                        client = self._sock.accept()
                        threading.Thread(target=self._peer, args=(client[0],)).start()
                    except:
                        pass

    def _peer(self, sock):
        self.peers += 1
        if self._encrypt:
            sock.send(b'1')
        else:
            sock.send(b'0')
        data = sock.recv(1)
        while (data == b''):
            time.sleep(0.008)
            data =  sock.recv(1)
        if self._encrypt:
            sock.sendall(self._public.export_key(format="DER"))
            data = sock.recv(256)
            while (len(data) < 256):
                time.sleep(0.008)
                data += sock.recv(256)
            data = self._decryptor.decrypt(data).split(b'\xFF')
            AES_E = AES.new(data[0], AES.MODE_CFB, IV=data[1])
            AES_D = AES.new(data[0], AES.MODE_CFB, IV=data[1])
            sock.send(b'0')
        data = sock.recv(64)
        while (data == b''):
            time.sleep(0.008)
            data = sock.recv(64)
        if self._encrypt:
            data = AES_D.decrypt(data)
        data = data.split(b"\xFF")
        success = False
        for user in range(0, len(self._users)):
            if (data[0] == bytes(self._users[user]._user, "utf8")) & (data[1] == bytes(self._users[user]._password, "utf8")):
                sock.send(b'0')
                connectedUser = self._users[user]
                success = True
                break
        if not (success):
            sock.send(b'4')
            self.peers -= 1
            return None
        while (self._running):
            request = sock.recv(256)
            while (len(request) < 256):
                time.sleep(0.008)
                request = sock.recv(256)
            if (self._encrypt):
                request = AES_D.decrypt(request)
            # Read
            if (request[:1] == b'0'):
                if (connectedUser._level == 1):
                    sock.send(b'1')
                    continue
                if request[1:2] == b'0':
                    try:
                        data = self.memstorage[request[2:request.index(b'\xFF')]]
                        sock.send(b'0')
                        data = blosc.compress(data, cname="blosclz")
                        if (self._encrypt):
                            AES_E.encrypt(data)
                        sock.sendall(data + b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF')
                        continue
                    except:
                        try:
                            fileIO = open(request[2:request.index(b'\xFF')], "rb")
                            for i in range(math.ceil((os.stat(request[2:request.index(b'\xFF')]).st_type + 6) / 1000000000) - 1):
                                data = blosc.compress(fileIO.read(1000000000), cname="blosclz")
                                if (self._encrypt):
                                    data = AES_E.encrypt(data)
                                sock.sendall(data)
                                while (sock.recv(1) == b''):
                                    time.sleep(0.002)
                            data = blosc.compress(fileIO.read(1000000000), cname="blosclz")
                            if (self._encrypt):
                                data = AES_E.encrypt(data)
                            sock.sendall(data + b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF')
                        except:
                            sock.send(b'2')
                else:
                    # List dir
                    pass
            # Write
            else:
                if (connectedUser._level == 0):
                    sock.send(b'1')
                    continue
                if request[1:2] == b'0':
                    try:
                        os.makedirs(os.path.dirname(connectedUser._path + request[2:request.find(b'\xFF')]), exist_ok=True)
                        fileIO = open(request[2:request.find(b'\xFF')], "wb")
                        chunk = b''
                        sock.send(b'0')
                        if (self._encrypt):
                            data = sock.recv(100000)
                            while ((b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF') not in data):
                                chunk += AES_D.decrypt(data)
                                if (len(chunk) >= 1000000000):
                                    fileIO.write(blosc.decompress(chunk))
                                    chunk = b''
                                    sock.send(b'0')
                                data = sock.recv(100000)
                            chunk += AES_D.decrypt(data[:data.find(b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF')])
                            fileIO.write(blosc.decompress(chunk))
                            fileIO.close()
                        else:
                            data = sock.recv(100000)
                            while ((b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF') not in data):
                                chunk += data
                                if (len(chunk) >= 1000000000):
                                    fileIO.write(blosc.decompress(chunk))
                                    chunk = b''
                                    sock.send(b'0')
                                data = sock.recv(100000)
                            chunk += data[:data.find(b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF')]
                            fileIO.write(blosc.decompress(chunk))
                            fileIO.close()
                    except:
                        sock.send(b'2')
                else:
                    size = int(request[request.find(b'\xFF') + 1: request.find(b'\xFF') + 1 + request[request.find(b'\xFF') + 1:].find(b'\xFF')])
                    if (size > ps.virtual_memory().inactive):
                        sock.send(b'3')
                        continue
                    sock.send(b'0')
                    data = sock.recv(100000)
                    while ((b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF') not in data):
                        time.sleep(0.002)
                        data += sock.recv(100000)
                    if (self._encrypt):
                        data = AES_D.decrypt(data[:len(data) - 6])
                    else:
                        data = data[:len(data) - 6]
                    self.memstorage[request[2:request.find(b'\xFF')]] = blosc.decompress(data)

    def addUser(self, user):
        if type(user) != User:
            raise Exception(b"Given user is not of User type.")
        self._users.append(user)

    def close(self):
        self._running = False
        self._sock.shutdown(socket.SHUT_RDWR)


class Client:
    def __init__(self, iph, user="", password=""):
        self._user = user
        self._password = password
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._key = Random.urandom(32)
        self._IV = Random.urandom(16)
        self._AES_E = AES.new(self._key, AES.MODE_CFB, IV=self._IV)
        self._AES_D = AES.new(self._key, AES.MODE_CFB, IV=self._IV)
        self._sock.connect((iph, 5500))
        data = self._sock.recv(1)
        while (data == b''):
            time.sleep(0.008)
            data = self._sock.recv(1)
        self._sock.send(b'0')
        self._is_encrypted = False
        if (data == b'1'):
            self._is_encrypted = True
            data = self._sock.recv(294)
            while (len(data) < 294):
                time.sleep(0.008)
                data += self._sock.recv(294)
            public = PKCS1_OAEP.new(RSA.importKey(data))
            encrptedKey = public.encrypt(self._key + b'\xFF' + self._IV)
            self._sock.sendall(encrptedKey)
            data = self._sock.recv(1)
            while (data == b''):
                time.sleep(0.008)
                data = self._sock.recv(1)
        send = bytes(self._user, "utf-8") + b"\xFF" + bytes(self._user, "utf-8")
        if self._is_encrypted:
            send = self._AES_E.encrypt(send)
        self._sock.send(send)
        data = self._sock.recv(1)
        while data == b'':
            time.sleep(0.008)
            data = self._sock.recv(1)
        if data != b'0':
            print("Auth failed with code " + str(data))

    def __call__(self, iph, user="", password=""):
        try:
            self._sock.close()
        except:
            pass
        self._key = Random.urandom(32)
        self._IV = Random.urandom(16)
        self._AES_E = AES.new(self._key, AES.MODE_CFB, IV=self._IV)
        self._AES_D = AES.new(self._key, AES.MODE_CFB, IV=self._IV)
        self._sock.connect((iph, 5500))
        data = self._sock.recv(1)
        while (data == b''):
            time.sleep(0.008)
            data = self._sock.recv(1)
        self._sock.send(b'0')
        self._is_encrypted = False
        if (data == b'1'):
            self._is_encrypted = True
            data = self._sock.recv(294)
            while (len(data) < 294):
                time.sleep(0.008)
                data += self._sock.recv(294)
            public = PKCS1_OAEP.new(RSA.importKey(data))
            encrptedKey = public.encrypt(self._key + b'\xFF' + self._IV)
            self._sock.sendall(encrptedKey)
            data = self._sock.recv(1)
            while (data == b''):
                time.sleep(0.008)
                data = self._sock.recv(1)
        send = bytes(self._user, "utf-8") + b"\xFF" + bytes(self._user, "utf-8")
        if self._is_encrypted:
            send = self._AES_E.encrypt(send)
        self._sock.send(send)
        data = self._sock.recv(1)
        while data == b'':
            time.sleep(0.008)
            data = self._sock.recv(1)
        if data != b'0':
            print("Auth failed with code " + str(data))

    # Reads data from file and sends it to the server
    def write_from_file(self, filepath, mode=FILE, name=""):
        if (name == ""):
            name = filepath
        size = bytes(str(os.stat(filepath).st_size), "utf8")
        self._sock.send(b'1' + bytes(str(mode), "utf8") + bytes(name, "utf8") + b'\xFF' + size + (b'\xFF' * (253 - len(name) - len(size))))
        response = self._sock.recv(1)
        while (response == b''):
            time.sleep(0.002)
            response = self._sock.recv(1)
        if (response != b'0'):
            # Add to log
            return False
        file = open(filepath, "rb")
        if (mode == 0):
            for i in range(math.ceil((int(size) + 6) / 1000000000) - 1):
                data = blosc.compress(file.read(1000000000), cname="blosclz")
                if (self._is_encrypted):
                    data = self._AES_E.encrypt(data)
                self._sock.sendall(data)
                while (self._sock.recv(1) == b''):
                    time.sleep(0.002)
            data = file.read(1000000000 - 6)
            if (self._is_encrypted):
                data = self._AES_E.encrypt(data)
            self._sock.sendall(data + b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF')
            return True
        data = blosc.compress(file.read(), cname="blosclz")
        if (self._is_encrypted):
            data = self._AES_E.encrypt(data)
        self._sock.sendall(data + b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF')
        return True

    # Reads data from buffer and sends it to the server
    def write_from_memory(self, data, name, mode=FILE):
        size = bytes(str(len(data)), "utf8")
        if (self._is_encrypted):
            self._sock.send(self._AES_E.encrypt(b'1' + bytes(str(mode), "utf8") + bytes(name, "utf8") + b'\xFF' + size +  (b'\xFF' * (253 - len(name) - len(size)))))
        else:
            self._sock.send(b'1' + bytes(str(mode), "utf8") + bytes(name, "utf8") + b'\xFF' + size +  (b'\xFF' * (253 - len(name) - len(size))))
        response = self._sock.recv(1)
        while (response == b''):
            time.sleep(0.002)
            response = self._sock.recv(1)
        if (response != b'0'):
            # Add to log
            print(response)
            return False
        data = blosc.compress(data, cname="lz4")
        if (self._is_encrypted):
            data = self._AES_E.encrypt(data)
        self._sock.sendall(data + b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF')
        return True

    # Reads from server
    def read(self, name, filename=""):
        if (self._is_encrypted):
            self._sock.send(self._AES_E.encrypt(b'00' + bytes(name, "utf8") + (b'\xFF' * (254 - len(name)))))
        else:
            self._sock.send(b'00' + bytes(name, "utf8") + (b'\xFF' * (254 - len(name))))
        response = self._sock.recv(1)
        while (response == b''):
            time.sleep(0.002)
            response = self._sock.recv(1)
        if (response != b'0'):
            # Add to log
            return b''
        if (filename != ""):
            try:
                os.makedirs(os.path.dirname(filename), exist_ok=True)
                fileIO = open(filename, "wb")
                chunk = b''
                self._sock.send(b'0')
                if (self._is_encrypted):
                    data = self._sock.recv(100000)
                    while ((b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF') not in data):
                        chunk += self._AES_D.decrypt(data)
                        if (len(chunk) >= 1000000000):
                            fileIO.write(blosc.decompress(chunk))
                            chunk = b''
                            self._sock.send(b'0')
                        data = self._sock.recv(100000)
                    chunk += self._AES_D.decrypt(data[:data.find(b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF')])
                    fileIO.write(blosc.decompress(chunk))
                    fileIO.close()
                else:
                    data = self._sock.recv(100000)
                    while ((b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF') not in data):
                        chunk += data
                        if (len(chunk) >= 1000000000):
                            fileIO.write(blosc.decompress(chunk))
                            chunk = b''
                            self._sock.send(b'0')
                        data = self._sock.recv(100000)
                    chunk += data[:data.find(b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF')]
                    fileIO.write(blosc.decompress(chunk))
                    fileIO.close()
            except:
                raise Exception("Could not save to file.")
        else:
            self._sock.send(b'0')
            data = self._sock.recv(100000)
            while ((b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF') not in data):
                time.sleep(0.002)
                data += self._sock.recv(100000)
            if (self._is_encrypted):
                data = self._AES_D.decrypt(data[:len(data) - 6])
            return blosc.decompress(data)

    # Gets a list of files and directories *** Not yet implemented
    def ls(self, mode=FILE, subdir=""):
        if ((mode == 0) & (subdir == "")):
            subdir = "./"
        self._sock.send(b'01' + bytes(subdir, "utf8") + (b'\xFF' * (254 - len(subdir))))

    # Deletes file, folder, or mem *** Not yet implemented
    def rm(self, path):
        self._sock.send(b'12' + bytes(path, "utf8") + (b'\xFF' * (254 - len(path))))