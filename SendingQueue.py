from Queue import Queue
from Models import Packet

class SendingQueue:

    packets = Queue()
    # messages


    @staticmethod
    def enqueue(packet):
        if SendingQueue.packets.Empty():
            SendingQueue.packets.put(packet)
            SendingQueue.dequeue()
        else:
            SendingQueue.packets.put(packet)


    @staticmethod
    def dequeue():
        from Socket import Socket
        packet = SendingQueue.packets.get()
        Socket.sendMessage(packet.message, packet.ip, True)


    @staticmethod
    def removePacket(messageId, packetId, ip):
        from Datapackets import Datapackets

        key = messageId + ip
        if SendingQueue.packets.has_key(key):
            for packet in SendingQueue.packets[key]:
                if Datapackets.getPacketId(packet) == packetId:
                    SendingQueue.packets[key].remove(packet)
                    if len(SendingQueue.packets[key]) == 0:
                        del SendingQueue.packets[key]

    @staticmethod
    def check(messageId, packetId, ip):
        from Datapackets import Datapackets

        key = messageId + ip
        if SendingQueue.packets.has_key(key):
            for packet in SendingQueue.packets[key]:
                if Datapackets.getPacketId(packet) == packetId:
                    return True
        return False


