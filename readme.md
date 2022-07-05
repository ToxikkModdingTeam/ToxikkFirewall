ToxikkFirewall
===

This is an attempt to counter the "Fake Player Bug" Denial-of-Service attack, which crashes TOXIKK and other UE3 based game servers by flooding it with fake player connections.  
There are several specialized versions of DoS tools tailered to specific game engines and protocols. In case of UE3/TOXIKK attacks happen over the game port, typically UDP 7777.  
This firewall is not specific to any game protocol and can probably be used for other games and applications too.

The general idea is to make the attack more "expensive" to execute by forcing it to keep its CPU threads longer alive (waiting for timeouts) and keep sending data.

The current implementation uses the following approaches:
- drop all UDP packages from a client IP:port for the first 3 seconds. The real game client will continue trying for more than 3 seconds, while the known DoS tool will give up after 2 seconds.
- when no packets are received within 30 seconds from a given client IP:port, the connection will be dropped. If more than 4 connections are dropped from the same IP, the IP will be blocked until restart.

The firewall works as a man-in-the-middle proxy on the application layer. It hides the real game server, which typically listens on the 0.0.0.0 "any-IP" address, by binding itself to the specific external 
IP address of the host and as such has priority to handle incoming packets.
A single proxy instance can handle multiple port numbers to protect multiple game server instances. All received packets are forwarded to the same port number on 127.0.0.1, where the game server is still 
reachable on the local machine.

A side effect of using the proxy is that the game server will only see 127.0.0.1:xxxx instead of the real IP:port addresses of game clients.
The proxy itself shows the IP:port of clients connecting to it and to which ports they get forwarded.


Usage
---
ToxikkFirewall.exe \<external-IPv4\> \<port1\> [\<port2\> ...]

where the port number is typically 7777