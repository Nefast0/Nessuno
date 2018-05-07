import thread, time

from Neighbors import Neighbors
from Config import Config
from Socket import Socket
from Crypto import Crypto
from Datapackets import Datapackets
from SendingQueue import SendingQueue

class SocketHandler:

    # start basic services
    @staticmethod
    def init():
        Socket() # init socket
        KeepAlive() # init keep alive background service


    # send same data to all the available neighbors
    @staticmethod
    def sendMessageToAll(data, receipient, port=0):
        if port == 0:
            port = Config.defaultPort

        data = Crypto.encrypt(data,receipient)
        for ip in Neighbors.getActiveNeighbors():
            SendingQueue.enqueue(data, ip)

    # send alive message
    @staticmethod
    def sendAlive(ip, port=0):
        if port == 0:
            port = Config.defaultPort

        # TODO: get Alive packet
        data = "x"
        Socket.sendMessage(data, ip, port)

    @staticmethod
    def sendAck(messageID, packetID, ip, port=0):
        if port == 0:
            port = Config.defaultPort
        print "Sending ACK"
        Socket.sendMessage('A'+ messageID + packetID, ip, port)

    @staticmethod
    def sendKeys(ip, port=0):
        if port == 0:
            port = Config.defaultPort
        for email in Crypto.listRecipientFingerprints().values():
            Socket.sendMessage(Crypto.exportPublicKey(email['fingerprint']), ip, port)



class KeepAlive:
    def __init__(self):
        try:
            thread.start_new_thread(KeepAlive.sendAliveToAll, ()) #start service in background
        except Exception as e:
            print "Error: KeepAlive failed\nDetails: " + e.message

    # send alive message to all the neighbors registered every 30sec
    @staticmethod
    def sendAliveToAll():
        while True:
            for ip in Neighbors.getNeighbors():
                # TODO: Add port opton to neighbours
                SocketHandler.sendAlive(ip)
            time.sleep(10)





