#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
from pyfingerprint.pyfingerprint import PyFingerprint
import paho.mqtt.client as mqtt
from Crypto.Cipher import AES
import subprocess
import time
def on_log(client, userdata, level, buf):
    print("log: ",buf) 
host_name = '192.168.1.5'
## Search for a finger
def on_message(client, userdata, message):
    global temp
    loop = 0
    temp = str(message.payload.decode("utf-8"))
    print("message received " ,str(message.payload.decode("utf-8")))

        
output=subprocess.check_output(["./crypto_test"], universal_newlines=True,shell=True)
    
print(output.splitlines())
secretA = output.splitlines()[0]
publicA = output.splitlines()[1]

client =mqtt.Client(client_id='FPR')
client.on_log=on_log
client.on_message = on_message
client.connect(host_name)
client.publish("publicA",publicA, qos=0, retain=True)


## Tries to initialize the sensor
try:
    f = PyFingerprint('/dev/ttyUSB0', 57600, 0xFFFFFFFF, 0x00000000)
    if ( f.verifyPassword() == False ):
        raise ValueError('The given fingerprint sensor password is wrong!')

except Exception as e:
    print('The fingerprint sensor could not be initialized!')
    print('Exception message: ' + str(e))
    exit(1)

## Gets some sensor information
print('Currently used templates: ' + str(f.getTemplateCount()) +'/'+ str(f.getStorageCapacity()))

## Tries to search the finger and calculate hash
try:
    ## print('Waiting for finger...')
    
    ## Wait that finger is read
    while ( f.readImage() == False ):
        pass

    ## Converts read image to characteristics and stores it in charbuffer 1
    f.convertImage(0x01)

    ## Searchs template
    result = f.searchTemplate()

    positionNumber = result[0]
    accuracyScore = result[1]

    ## else:
        ## print('Found template at position #' + str(positionNumber))
        ## print('The accuracy score is: ' + str(accuracyScore))
    ## result1 = f.loadTemplate(positionNumber)
    ## OPTIONAL stuff
    ##
    ##  print('sa')
    ## Loads the found template to charbuffer 1
    f.loadTemplate(positionNumber, 0x01)
    
    fingerTemplate = [0] * 524
    bytesReceived = f.downloadCharacteristics(0x01)
    uindx = 9
    index = 0
    
    while (index < 534) :
       
        while (index < uindx):
            index+= 1
        uindx += 256
        
        while (index < uindx-8) :
            
            fingerTemplate[index] = bytesReceived[index]
            index+=1
        while (index + uindx-8 < uindx) :
            print(index)
            fingerTemplate[index] = bytesReceived[index]
            index+=1
        uindx += 2
        while (index < uindx) :
            index+= 1
        uindx = index + 9;
    ##  print('sa2')
    characterics1 = str(bytesReceived).encode('utf-8')
    characterics = str(fingerTemplate).encode('utf-8')
    ## Downloads the characteristics of template loaded in charbuffer 1
    ##characterics = str(f.downloadCharacteristics(0x01)).encode('utf-8')
    ## print('filtresiz template: ' + characterics1.decode("utf-8"))
    
    ## print('SHA-2 hash of filtresiz: ' + hashlib.sha256(characterics1).hexdigest())
    ## print('Characterics of template: ' + characterics.decode("utf-8"))
    ## Hashes characteristics of template 'SHA-2 hash of template: ' +
    
    if ( positionNumber == -1 ):
        print('No match found!')
     ##hash a random number instead
        
        
    m = hashlib.sha256()
    m.update(characterics)
    fp=m.hexdigest()
    
    temp = '0'
    print('finger hashed: ' + fp)
    
    ##publicB = mqtt.receive()
    client.loop_start()

    client.subscribe('publicB')
    time.sleep(1) 
    client.loop_stop()
    publicB = temp
    print('publicB is: ' + publicB)
    args = "./crypto_test " + secretA + " "+ publicB
    print(args)
    output = subprocess.check_output([args], universal_newlines=True,shell=True)
    agreement=output
    
    print('generated agreement: ' + str(agreement))
    
    m = hashlib.sha256()
    m.update(agreement.encode())
    key = m.hexdigest()
    key = key[:len(key)//2]
    print('key is ' + key)
    obj = AES.new(key, AES.MODE_CBC, 'This is an IV456')
    ciphertext = obj.encrypt(fp)
    print('ciphertext is: ' + str(ciphertext))
    
    ## send cipher via mqqtt
  
    client.publish("FPhash",ciphertext, qos=0, retain=True)

except Exception as e:
    print('Operation failed!')
    print('Exception message: ' + str(e))
    exit(1)
