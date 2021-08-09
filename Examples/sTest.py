import time
import S3DTP as dtp

u = dtp.User(access=dtp.RW)
s = dtp.Server()
# No encryption
# s = dtp.Server(encryption=False)
s.addUser(u)

last = s.lastChanged

while True:
    if (last != s.lastChanged):
        # Do your operation here
        print(str(s.lastChanged) + " was added/overwritten.")
        ### End operation ###
        last = s.lastChanged
    time.sleep(0.002)
    # shellInput = input(">>>")
    # eval(shellInput)
