#!/bin/env python3
import socket

port = 4598
password = "@&asuysl*9712jayts$7"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((input("IP: "),port))

s.send(bytes(password+'\n\n','utf-8'))
todo = input("what to do? a/v")
s.send(bytes(todo,'utf-8'))
if todo == "a":
    data = input("Notification: ")
    s.send(bytes(data,'utf-8'))
    print(data)
else:
    i = 0
    while i < 20:
        data = s.recv(100)
        print(data.decode('utf-8')+"\n")
        i+=1
