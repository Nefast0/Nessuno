from Crypto import Crypto
from Datapackets import Datapackets
from Joiner import Joiner
from Transit_Handler import Transit_Handler
from SendingQueue import SendingQueue

class Receiver:

    @staticmethod
    def readOrForward(message):
        print "Start Decryption"
        print message
        gpg = Crypto()
        result = gpg.decrypt(message)
        if result:
            print "Message:\n" + result
            return True
        else:
            print result
            return False # Forward


    @staticmethod
    def parse(data, addr):

        messages = {
            'M': Receiver.message,
            'K': Receiver.key,
            'A': Receiver.ack,
            'x': Receiver.alive
        }
        messages.get(data[0][:1], Receiver.invalidPacket)(data, addr)

    @staticmethod
    def message(data, addr):
        from SocketHandler import SocketHandler
        print "Before check transit"
        if Transit_Handler.add(data):
            print "after check transit"
            SocketHandler.sendAck(Datapackets.getMessageId(data), Datapackets.getPacketId(data), addr)
            print "adding to join"
            print "Packet: " + data
            Joiner.getPacket(data, addr)
            print Joiner.messages

    @staticmethod
    def key(data, addr):
        gpg = Crypto()
        gpg.importPublicKey(data[1:])

    @staticmethod
    def ack(data, addr):
        SendingQueue.removePacket(data[1:5], data[5:9], addr)
        SendingQueue.dequeue(data[1:5], addr)

    @staticmethod
    def alive(data, addr):
        pass

    @staticmethod
    def invalidPacket(data, addr):
        print "Invalid packet received"

if __name__ == "__main__":
    m = """K-----BEGIN PGP PUBLIC KEY BLOCK-----
        Version: GnuPG v2
        
        mQENBFkZrzcBCADJhkgJ9vdJOvX43Sg4y/5/PXedt0ThpIMtEA8eqsfHFWBcPTiI
        wlzZoYsekxlXzFg3/3w9nIfcXPLR0AfzOaSQXaka6Zm84+B4qvtarvwbvwrLKF3r
        563T8IStLmMHUiqseUWch7IXLE1VDPrVWuPO3mkTzuQg4hAHpUqXjcAXw0M/yhPb
        ymOZOCOwpl86OrKkcP+1q+Wm8J6EF58k9Fp5ZO6LGh6ZfY5QhC9kr88+IFlke7cv
        czkfbQmRpVkAPg6bWkT8Ut1niWsw5WDKMI+4vSKz+CC5kKVv3m4Z5DLP06WT8vX5
        0neGhAxsc9C3SMLKNF61fxwS4bPLT3YrA6NpABEBAAG0IEF1dG9nZW5lcmF0ZWQg
        S2V5IDx0ZXN0QHRlc3QuaXQ+iQE5BBMBCAAjBQJZGa83AhsvBwsJCAcDAgEGFQgC
        CQoLBBYCAwECHgECF4AACgkQMFBHzPD7CYzZ9Qf/Xxqi3Tc/ZYGkPaAqE8+P8TKm
        pj2k2N7lVRMmRxBViZvVn7KirA0Hljw+sl2oUw0oqKrV2+FR/YYRG5wd+6vMV8lT
        v6UfRSOAsTrRDMUjVnENPCmd036djykept8Hllzs+6TaFiutmsgBK2NORacLjFag
        n6AV8drZ5+3lHN2YOTBblJlGduOBMFdVFMNUz2rRFAMfdZ6steF3akHsGfq4FWh2
        nDLbK9Pk/buEfQK6C0dkqL+zpoVVb9vRAgZHJzUbiXoZhq/VMJtW8+K3dbMYPEqG
        4pq5is6nXsewuv4WerfdOsfrVehWnYtTGRCZ4Zs/hKnV6749pMEcr9TB/52ykg==
        =etWb
        -----END PGP PUBLIC KEY BLOCK-----"""
    Receiver.parse(m,'127.0.0.1')
