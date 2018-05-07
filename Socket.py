import socket
import thread
import time
from Config import Config
from Neighbors import Neighbors
from Receiver import Receiver
from SendingQueue import SendingQueue

class Socket:

    def __init__(self, port=0):
        if port == 0: # Set default port
            port = Config.defaultPort
        else:
            pass
        try:
            thread.start_new_thread(self.listen, (port,)) # Start listening
        except Exception as e:
            print("Error: unable to start the socket\nDetails: " + e)

    # Send a message with data to ipaddress to the default port unless specified
    @staticmethod
    def sendMessage(data, ipAddress, resend=False, port=0):  # TODO: resend flag trigger thread, check inTransit
        if port == 0:
            port = Config.defaultPort

        sock = socket.socket(socket.AF_INET,  # Internet
                             socket.SOCK_DGRAM)  # UDP
        sock.sendto(data, (ipAddress, port))
        sock.close()
        #thread.start_new_thread(Socket.resend, (data, ipAddress, port,))  # Resend timeout

    @staticmethod
    def resend(data, ipAddress, port=0, counter=5):
        from Datapackets import Datapackets

        if port == 0:
            port = Config.defaultPort

        time.sleep(30)
        if SendingQueue.check(Datapackets.getMessageId(data), Datapackets.getPacketId(data), ipAddress):
            print("resending")
            sock = socket.socket(socket.AF_INET,  # Internet
                                 socket.SOCK_DGRAM)  # UDP
            sock.sendto(data, (ipAddress, port))
            sock.close()
            thread.start_new_thread(Socket.resend, (data, ipAddress, port, --counter))  # Resend timeout

    # Function loop waiting for messages (background)
    def listen(self, port):
        ip = ''
        sock = socket.socket(socket.AF_INET,  # Internet
                             socket.SOCK_DGRAM)  # UDP

        # sock.setsockopt(S, SO_REUSEADDR, 1)
        sock.bind((ip, port))

        while True:
            data, addr = sock.recvfrom(1024)  # buffer size is 1024 bytes
            print "received message:", data
            self.readData(data, addr[0])
        sock.close()

    # Pass the data to Transit Handler to check
    # We should check whether the data contains ack, message or alive packet
    def readData(self, data, addr):
        #print "Received: " + data
        Neighbors.stillAlive(addr) #notify Neighbors that this node is active
        Receiver.parse(data, addr)


if __name__ == "__main__":
    s = Socket()
    while True:
        d = raw_input("Insert message\n")
        Socket.sendMessage("asd", "192.168.0.17")
