#!/usr/bin/env python
# -*- coding: utf-8 -*-

import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
import subprocess
import time
import hashlib
import sys

def on_connect(client, userdata, flags, rc):
     loop=0
     print("connected")
     client.connected_flag=True
def on_message(client, userdata, message):
    global temp
    loop = 0
    temp = str(message.payload.decode("utf-8"))
    print("message received " ,str(message.payload.decode("utf-8")))

def on_log(client, userdata, level, buf):
    print("log: ",buf)   
host_name = '192.168.1.5'
## 


loop=1
output=subprocess.check_output(["./crypto_test"], universal_newlines=True,shell=True)
print(output.splitlines())
secretB = output.splitlines()[0]
publicB = output.splitlines()[1]
publicA = '0'
temp = '0'
client =mqtt.Client(client_id='Server')
print('sa1')
client.on_message = on_message
client.on_connect = on_connect
client.on_log=on_log
client.connect(host_name)
client.loop_start()

temp = '0'
client.publish("publicB",publicB, qos = 0, retain=True)
client.subscribe('publicA')
time.sleep(1) 
client.loop_stop()

publicA = temp
print('publicA: ' + publicA)
args = "./crypto_test " + secretB + ' '+ publicA
output = subprocess.check_output([args], universal_newlines=True,shell=True)
agreement=output

    
## receive mqtt and decipher text
loop=1
client.loop_start()

client.subscribe('FPhash')
time.sleep(5) 
while loop == 1:
    time.sleep(0.5)
client.loop_stop()

ciphertext = temp
print(ciphertext)

m = hashlib.sha256()
m.update(agreement.encode())
key = m.hexdigest()
key = key[:len(key)//2]
print('key is: ' + key)

time.sleep(5)

obj2 = AES.new(key, AES.MODE_CBC, 'This is an IV456')
print('hash is: ' + obj2.decrypt(ciphertext))


