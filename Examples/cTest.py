import S3DTP as dt

data = b'Testing this code.'

client = dt.Client("localhost")

print(client.write_from_file("cTest.txt", name="WFFTF.txt"))
print(client.write_from_file("cTest.txt", mode=dt.MEM, name="WFFTM"))
print(client.write_from_memory(data, name="WFMTF.txt"))
print(client.write_from_memory(data, mode=dt.MEM, name="WFMTM"))

client.read("WFFTF.txt", filename="_WFFTF.txt")
f = open("_WFFTF.txt", "rb")
if (f.read() == data):
    print("Pass")
else:
    print("Fail")
f.close()
if (client.read("WFFTM") == data):
    print("Pass")
else:
    print("Fail")
client.read("WFMTF.txt", filename="_WFMTF.txt")
f = open("_WFMTF.txt", "rb")
if (f.read() == data):
    print("Pass")
else:
    print("Fail")
f.close()
if (client.read("WFMTM") == data):
    print("Pass")
else:
    print("Fail")
print(client.ls())
print(client.rm("_WFFTF.txt"))
print(client.ls(mode=1))
print(client.rm("WFFTM"))
print(client.ls())
print(client.rm("_WFMTF.txt"))
print(client.ls(mode=1))
print(client.rm("WFMTM"))
print(client.ls())
print(client.ls(mode=1))
