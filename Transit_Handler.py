from Datapackets import Datapackets
import time

class Transit_Handler:

    intransit = {}

    @staticmethod
    def add(packet):
        print "Trying to add the packet"
        key = Datapackets.getPacketId(packet)
        if Transit_Handler.intransit.has_key(key):
            if Transit_Handler.intransit[key] <= int(time.time()): #check the timestamp
                print "Drop"
                return True #drop
            else:
                print "Check ok"
                return False
        else:
            Transit_Handler.intransit[key] = int(time.time()) #adding packetID-timestamp
            return True

    def __repr__(self):
       for element in self.intransit:
            print element
       return ''

if __name__ == "__main__":
    t = Transit_Handler()
    ID = t.extractPacketID('0b0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001010101010101010101010101010101010101010101010101010101010101000000000000000')
    print ID
    print t.add(ID)
    print t.add(ID)
    repr(t)