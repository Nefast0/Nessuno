import zlib
from Config import *
import time
import random
from SendingQueue import SendingQueue

class Datapackets:

    #header -> 23 bytes
    #payload -> 485 bytes

    #DataType - 1 byte -> 'M', 'X', 'K', 'A'
    #Timestamp - 10 bytes
    #Seq number - 4 bytes -> starting from 0
    #Packet last - 4 bytes
    #Packet ID - 4 bytes
    #Message ID - 4 bytes
    #Payload -> encrypted max 485 bytes
    #CRC - 10 bytes

    def __init__(self, maxSize=0):
        if maxSize == 0:
            self.maxSize = Config.maxSizeUdp #establish max size of the UDP packet
        else:
            self.maxSize = maxSize
        self.packets = [] #list that stores all processed packets
        self.packetIp = ""
        self.ready = []

    @staticmethod # -- changed to static
    def calculateCRC(dataString): #calculates CRC from dataString provided as an argument of the method
        return (zlib.crc32(dataString)% 2**32) #to create unsigned crc and deleting L added by python conversion

    @staticmethod
    def getDataType(packet):
        return packet[0]

    @staticmethod
    def getTimestamp(packet):
        return packet[1:11]

    @staticmethod
    def getSeqNumber(packet):
        return packet[11:15]

    @staticmethod
    def getPacketLast(packet):
        return packet[15:19]

    @staticmethod
    def getPacketId(packet):
        return packet[19:23]

    @staticmethod
    def getMessageId(packet):
        return packet[23:27]

    @staticmethod
    def getPayload(packet):
        return packet[27:-10]

    @staticmethod
    def getCRC(packet):
        return packet[-10:]

    @staticmethod #created for Reliability, CRC verification
    def verifyCRC(packet):
        if (str(Datapackets.calculateCRC(packet)) == str(Datapackets.getCRC(packet))): #if CRC is the same, return True, otherwise return False
            return True
        return False

    def split_message(self,encrypted_message,ip):
        if len(encrypted_message)*8 > self.maxSize: #if splitting needed
            while (encrypted_message): #ASCII uses 1 byte to encode each char, so multiplied by 8 the number of characters
                if len(encrypted_message) > self.maxSize:
                    packet = encrypted_message[0:self.maxSize] #first slice of message from first char to maxSize-1
                    encrypted_message = encrypted_message[self.maxSize:] #rest of message
                    self.packets.append(packet)  # adding packet to packet array
                else: #last chunk goes here
                    packet = encrypted_message[0:self.maxSize]  # first slice of message from first char to maxSize-1
                    encrypted_message = encrypted_message[self.maxSize:]  # rest of message
                    self.packets.append(packet)  # adding packet to packet array
                    break #loop break
            self.packetIp = ip


        else: #if not splitting needed
            self.packets.append(encrypted_message)  # adding packet to packet array
            self.packetIp = ip

        self.construct_packets()

    def calculateFourByte(self,value): #creates a 4 byte value for LastPacket
        val = str(value)
        while (len(val))<4:
            val = "0" + val
        return val

    def construct_packets(self,datatype='M'):
        if datatype == 'M':
            messageID = self.calculateFourByte(random.randint(0,9999))
            lastPacket = self.calculateFourByte(len(self.packets) - 1) #substract last part - IP address and also starting seq from 0
            seq = "0000"
            for element in self.packets: #do not take last number, which is IP
                header = 'M' + str(int(time.time())+Config.TTL)
                packetID = self.calculateFourByte(random.randint(0,9999))
                header = header + seq + lastPacket + packetID + messageID
                message = header + element
                packet = message + str(Datapackets.calculateCRC(message))
                seq = str(self.calculateFourByte(int(seq) + 1))
                self.ready.append(packet)

            SendingQueue.enqueue(self.ready, self.packetIp)


    #output -> first element is number of packets and then each packet sequentally message+hash appended
if __name__ == "__main__":
    t = Datapackets()
    w = t.calculateCRC('hello-world') #example of CRC calculation
    print w #correct
    t.split_message("Hola Buenas Tardes a Todos","192.168.0.1")
    t.construct_packets()
    print t.getDataType("Hello")