# Networking
import socket

# Compression
import blosc

# Encryption/Hash
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Cipher import Salsa20
from Crypto import Random

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

# Users
from .User import User

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
        self.lastChanged = None
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
        import random
        self.peers += 1
        if self._encrypt:
            sock.send(b'1')
        else:
            sock.send(b'0')
        data = sock.recv(1)
        while (data == b''):
            time.sleep(0.0001)
            data =  sock.recv(1)
        if self._encrypt:
            sock.sendall(self._public.export_key(format="DER"))
            data = sock.recv(256)
            while (len(data) < 256):
                time.sleep(0.004)
                data += sock.recv(256)
            data = self._decryptor.decrypt(data)
            key = data[:32]
            random.seed(data[32:])
            sock.send(b'0')
        data = sock.recv(64)
        while (data == b''):
            time.sleep(0.008)
            data = sock.recv(64)
        if self._encrypt:
            data = Salsa20.new(key, random.randbytes(8)).decrypt(data)
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
                time.sleep(0.002)
                request = sock.recv(256)
            if (self._encrypt):
                request = Salsa20.new(key, random.randbytes(8)).decrypt(request)
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
                            data = Salsa20.new(key, random.randbytes(8)).encrypt(data)
                        sock.sendall(data + b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF')
                        continue
                    except:
                        try:
                            fileIO = open(request[2:request.index(b'\xFF')], "rb")
                            size = bytes(str(math.ceil((os.stat(request[2:request.index(b'\xFF')]).st_size + 6) / 1000000000)), "utf8")
                            sock.send(b'0' + size)
                            for i in range(int(size) - 1):
                                data = blosc.compress(fileIO.read(1000000000), cname="blosclz")
                                if (self._encrypt):
                                    data = Salsa20.new(key, random.randbytes(8)).encrypt(data)
                                sock.sendall(data)
                                while (sock.recv(1) == b''):
                                    time.sleep(0.002)
                            data = blosc.compress(fileIO.read(1000000000), cname="blosclz")
                            if (self._encrypt):
                                data = Salsa20.new(key, random.randbytes(8)).encrypt(data)
                            sock.sendall(data + b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF')
                            fileIO.close()
                        except Exception as e:
                            print(e)
                            sock.send(b'2')
                else:
                    # List dir
                    if (request[2:request.find(b'\xFF')] == b'\xEE'):
                        data = bytes(str(list(self.memstorage.keys())), "utf8")
                        if (self._encrypt):
                            sock.sendall(Salsa20.new(key, random.randbytes(8)).encrypt(data) + b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF')
                        else:
                            sock.sendall(data + b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF')
                    else:
                        if (request[2:request.find(b'\xFF')] == b'./'):
                            data = bytes(str(os.listdir(connectedUser._path)), "utf8")
                        else:
                            data = bytes(str(os.listdir(connectedUser._path + b'/' + request[2:request.find(b'\xFF')])), "utf8")
                        if (self._encrypt):
                            sock.sendall(Salsa20.new(key, random.randbytes(8)).encrypt(data) + b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF')
                        else:
                            sock.sendall(data + b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF')
            # Write
            else:
                if (connectedUser._level == 0):
                    sock.send(b'1')
                    continue
                if (request[1:2] == b'0'):
                    size = int(request[request.find(b'\xFF') + 1: request.find(b'\xFF') + 1 + request[request.find(b'\xFF') + 1:].find(b'\xFF')])
                    try:
                        try:
                            os.remove(connectedUser._path + b'/' + request[2:request.find(b'\xFF')])
                        except:
                            pass
                        os.makedirs(os.path.dirname(connectedUser._path + request[2:request.find(b'\xFF')]), exist_ok=True)
                        fileIO = open(connectedUser._path + b'/' + request[2:request.find(b'\xFF')], "ab")
                        sock.send(b'0')
                        if (self._encrypt):
                            for i in range(math.ceil(size / 1000000000)):
                                data = sock.recv(100000)
                                while ((b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF') not in data):
                                    time.sleep(0.001)
                                    data += sock.recv(100000)
                                fileIO.write(blosc.decompress(Salsa20.new(key, random.randbytes(8)).decrypt(data[:len(data) - 6])))
                                sock.send(b'0')
                            fileIO.close()
                        else:
                            for i in range(math.ceil(size / 1000000000)):
                                data = sock.recv(100000)
                                while ((b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF') not in data):
                                    time.sleep(0.0005)
                                    data += sock.recv(100000)
                                fileIO.write(blosc.decompress(data[:len(data) - 6]))
                                sock.send(b'0')
                            fileIO.close()
                        self.lastChanged = connectedUser._path + b'/' + request[2:request.find(b'\xFF')]
                    except:
                        sock.send(b'2')
                elif (request[1:2] == b'1'):
                    size = int(request[request.find(b'\xFF') + 1: request.find(b'\xFF') + 1 + request[request.find(b'\xFF') + 1:].find(b'\xFF')])
                    if (size > ps.virtual_memory().inactive):
                        sock.send(b'3')
                        continue
                    sock.send(b'0')
                    data = sock.recv(100000)
                    while ((b'\xAA' + b'\xBB' + b'\xCC' + b'\xDD' + b'\xEE' + b'\xFF') not in data):
                        time.sleep(0.00075)
                        data += sock.recv(100000)
                    if (self._encrypt):
                        data = Salsa20.new(key, random.randbytes(8)).decrypt(data[:len(data) - 6])
                    else:
                        data = data[:len(data) - 6]
                    self.memstorage[request[2:request.find(b'\xFF')]] = blosc.decompress(data)
                    sock.send(b'0')
                    self.lastChanged = request[2:request.find(b'\xFF')]
                else:
                    try:
                        del self.memstorage[request[2:request.index(b'\xFF')]]
                        sock.send(b'0')
                    except:
                        try:
                            os.remove(connectedUser._path + b'/' + request[2:request.index(b'\xFF')])
                            sock.send(b'0')
                        except:
                            sock.send(b'2')

    def addUser(self, user):
        if type(user) != User:
            raise Exception(b"Given user is not of User type.")
        self._users.append(user)

    def close(self):
        self._running = False
        self._sock.shutdown(socket.SHUT_RDWR)
