#!/bin/env python3
import socket
import ssl
import getpass

port = 4598
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_socket = ssl.wrap_socket(s,ssl_version=ssl.PROTOCOL_TLS);
ssl_socket.connect((input("IP: "),port))

username = input("Username: ")
ssl_socket.send(bytes([len(username)]))
ssl_socket.send(bytes(username,"utf-8"))

password = getpass.getpass("Password: ")
ssl_socket.send(bytes([len(password)]))
ssl_socket.send(bytes(password,'utf-8'))
todo = input("what to do? a/v")
ssl_socket.send(bytes(todo,'utf-8'))
if todo == "a":
    data = input("Notification: ")
    ssl_socket.send(bytes(data,'utf-8'))
    print(data)
else:
    i = 0
    while i < 20:
        data = ssl_socket.recv(100)
        print(data.decode('utf-8')+"\n")
        i+=1
