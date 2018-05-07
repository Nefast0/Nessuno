from Datapackets import Datapackets
from SendingQueue import SendingQueue
from Neighbors import Neighbors

class Joiner:
    messages = {}
    # messages
    # - MessageID dict
    #   -- nPackets int
    #   -- packets packet[]

    @staticmethod
    def getPacket(packet, ip):
        from Receiver import Receiver

        if Joiner.messages.has_key(Datapackets.getMessageId(packet)):
            Joiner.messages[Datapackets.getMessageId(packet)]['packets'].insert(int(Datapackets.getSeqNumber(packet)), packet)

            # Check if all the packets have been received
            if int(Joiner.messages[Datapackets.getMessageId(packet)]['nPackets']) == len(Joiner.messages[Datapackets.getMessageId(packet)]['packets']):
                print "Message Completed"
                payload = ''
                for packet in Joiner.messages[Datapackets.getMessageId(packet)]['packets']:
                    payload += Datapackets.getPayload(packet)
                if Receiver.readOrForward(payload):
                    pass # Read
                else:
                    # Forward
                    print "forward"
                    for ipNeigh in Neighbors.getActiveNeighbors():
                        if ipNeigh != ip:
                            SendingQueue.enqueue(Joiner.messages[Datapackets.getMessageId(packet)]['packets'], ipNeigh)

        else:
            Joiner.messages[Datapackets.getMessageId(packet)] = {}
            Joiner.messages[Datapackets.getMessageId(packet)]['nPackets'] = int(Datapackets.getPacketLast(packet)) + 1
            Joiner.messages[Datapackets.getMessageId(packet)]['packets'] = []
            Joiner.messages[Datapackets.getMessageId(packet)]['packets'].append(packet)


if __name__ == "__main__":
    print Datapackets.getMessageId("0123456789abcdfefghilmnopqrst")