import time


class Neighbors:

    neighbors = [] # array with all the possible neighbors to check
    active_neighbors = {} #array with only available neighbors

    # add a new neighbor and check connection
    @staticmethod
    def addNeighbor(ip):
        Neighbors.neighbors.append(ip) #add to the array neighbors
        if not Neighbors.active_neighbors.has_key(ip):
            delay = Neighbors.helloNeighbor(ip) #check connection and calculate delay
            Neighbors.active_neighbors[ip] = delay #once connection has been created, add it to the available neighbors
            #Neighbors.sendKeys(ip)

    # Hole Punching hello
    # Keeps sending alive packets to destination until it replies
    # TODO: timeout
    @staticmethod
    def helloNeighbor(ip):
        Neighbors.active_neighbors[ip] = ''
        while Neighbors.active_neighbors[ip] == '':
            pass
        print 'hello'
        return int(time.time())

    @staticmethod
    def getActiveNeighbors():
        return Neighbors.active_neighbors.keys()

    @staticmethod
    def getNeighbors():
        return Neighbors.neighbors

    #Remove neighbor from both structures
    @staticmethod
    def removeNeighbor(self, ip):
        del self.neighbors[ip]
        del self.active_neighbors[ip]

    #called whenever I receive any message from a neighbor
    @staticmethod
    def stillAlive(ip):
        Neighbors.active_neighbors[ip] = int(time.time())

    @staticmethod
    def sendKeys(ip):
        from Keyring import Keyring
        from Socket import Socket
        keys = Keyring.keys
        for key in keys:
            Socket.sendMessage('K' + (key), ip)

