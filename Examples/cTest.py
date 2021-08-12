import S3DTP as dt

data = b'Testing this code.'

client = dt.Client("localhost")

print(client.write_from_file("cTest.txt", name="Write_from_file_to_file.txt.txt"))
print(client.write_from_file("cTest.txt", mode=dt.MEM, name="Write_from_file_to_memory"))
print(client.write_from_memory(data, name="_Write_from_memory_to_file.txt"))
print(client.write_from_memory(data, mode=dt.MEM, name="Write_from_memory_to_memory"))

client.read("Write_from_file_to_file.txt", filename="_Write_from_file_to_file.txt")
f = open("_Write_from_file_to_file.txt", "rb")
if (f.read() == data):
    print("Pass")
else:
    print("Fail")
f.close()
if (client.read("Write_from_file_to_memory") == data):
    print("Pass")
else:
    print("Fail")
client.read("Write_from_memory_to_file.txt", filename="_Write_from_memory_to_file.txt")
f = open("_Write_from_memory_to_file.txt", "rb")
if (f.read() == data):
    print("Pass")
else:
    print("Fail")
f.close()
if (client.read("Write_from_memory_to_memory") == data):
    print("Pass")
else:
    print("Fail")
print(client.ls())
print(client.rm("_Write_from_file_to_file.txt"))
print(client.ls(mode=1))
print(client.rm("Write_from_file_to_memory"))
print(client.ls())
print(client.rm("_Write_from_memory_to_file.txt"))
print(client.ls(mode=1))
print(client.rm("Write_from_memory_to_memory"))
print(client.ls())
print(client.ls(mode=1))
