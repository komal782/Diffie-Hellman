FILES
------
icludes:
- Client.java
	communicates betweent the client and the server. Changed the getKey() method only.
- ServerThread.java
	this communicates between the client and server, changed the getKey() method just like 
	for the client, This is where I create my primes p and q.
- Sever.java
	The server that communicates with the client, I didn't change this file at all.


DESCRIPTION
-----------

The way that I implemented the DH protocol is, in the server thread in the getKey() method I
start by generating a random prime, the prime numbers are stored as bigInteger values. 
This is then the q value. Then I calculate the prime p, by p = 2q + 1. Then the server sends 
the p value to the client. Then the client (in Client.java in getKey() method) uses the p
value to generate the a value. Then the server send the g value that is randomly generated to
the Client. The client uses this for g^a (mod p), and the server does the same after
generating the b value to get g^b (mod p). The server and Client both send their values to
each other and calculate g^ab (mod p). Then I generate the key using that value, which should
be the same for both server and client.

COMPILE
-------

javac *.java
java Server [port]
java Client [server number] [port]
