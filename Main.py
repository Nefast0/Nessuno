from SocketHandler import SocketHandler
from Neighbors import Neighbors
from Crypto import Crypto
from Config import Config

# function to add a neighbor
def add(*param):
    if len(param) == 1:
        Neighbors.addNeighbor(param[0])
    elif len(param) > 1:
        pass  #Neighbors.addNeighbor(param[0], param[1])
    else:
        print "Arguments are missing"

# function to list emails
def listNodes(*param):
    gpg = Crypto()
    for key in gpg.listRecipientFingerprints().keys():
        print key + '\n'

# function to list emails
def generate(*param):
    gpg = Crypto()

    if len(param) == 1: # only email
        email = param[0]
        print gpg.generateKeyPair(email)

    elif len(param) == 2: # email and passphrase
        email = param[0]
        passphrase = param[1]
        print gpg.generateKeyPair(email, passphrase)

    elif len(param) > 2: # email and passphrase
        print "Too many arguments"
    else:
        print "Arguments are missing"

# function to send a message to a user
def sendTo(*param):
    gpg = Crypto()
    receipient = param[0]
    message = ' '.join(param[1:])
    if True: # if we got the public key of the receiver
        SocketHandler.sendMessageToAll(message, receipient)
    else:
        pass

# if no command was found
def commandNotFound(*param):
    print "Command not found"

# List of all commands available in the chat
# Usage "/command param1 param2 ..."
# syntax for mapping the commands:
# 'command':functionName
# functionName must request *param as an argument and then check whether the params are correct
commandOptions = {
        'add': add,
        'listNodes': listNodes,
        'sendTo': sendTo,
        'generate': generate
    }

SocketHandler.init()
Crypto.loadKeys()

#/add 192.168.0.27

while True:
    message = raw_input("Insert Message\n")

    if message.startswith('/'): # if this is a command
        message = message.split(' ')
        command = message.pop(0).lstrip('/') # isolate the command

        commandOptions.get(command, commandNotFound)(*message) # message contains all the parameters

    else:
        pass # if it's not a command, it's nothing




