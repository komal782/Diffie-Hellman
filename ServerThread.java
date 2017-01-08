
/**
 * The code was taken from Mike Jacobson, the method getKey() was the only method that I changed
 */

import java.net.*;
import java.io.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.math.*;
import java.util.*;

/**
 * This class represents a thread to deal with clients who connect to Server.  
 * Put what you want the thread to do in it's run() method.
 *
 * @author Mike Jacobson
 * @version 1.0, October 23, 2013
 */
public class ServerThread extends Thread
{
    private Socket sock;  //The socket it communicates with the client on.
    private Server parent;  //Reference to Server object for message passing.
    private int idnum;  //The client's id number.
    private DataOutputStream out;
    private DataInputStream in;
    private SecretKeySpec key;   // AES encryption key


    /**
     * Utility for printing protocol messages
     * @param s protocol message to be printed
     */
    private void debug(String s) {
	if(parent.getDebug()) 
	    System.out.println("Debug Server: " + s);
    }



    /**
     * Constructor, does the usual stuff.
     * @param s Communication Socket.
     * @param p Reference to parent thread.
     * @param id ID Number.
     */
    public ServerThread (Socket s, Server p, int id)
    {
	parent = p;
	sock = s;
	idnum = id;
	in = null;
	out = null;
    }


	
    /**
     * Getter for id number.
     * @return ID Number
     */
    public int getID ()
    {
	return idnum;
    }


	
    /**
     * Getter for the socket, this way the parent thread can
     * access the socket and close it, causing the thread to
     * stop blocking on IO operations and see that the server's
     * shutdown flag is true and terminate.
     * @return The Socket.
     */
    public Socket getSocket ()
    {
	return sock;
    }



    /**
     ********************************* creates the key *******************************************************************************************************
     */
    public void getKey() {

	boolean po = true;
	byte[] clientTemp;
	BigInteger qprime, one, two, temp, pprime, g, z, serverKey, b, clientKey, seed;
	SecureRandom rnd = new SecureRandom();
	//initializing all of the big integer values
	two = new BigInteger("2");
	one = new BigInteger("1");
	z = new BigInteger("0");
	g = new BigInteger("0");
	pprime = new BigInteger("0");
	qprime = new BigInteger("0");
	serverKey = new BigInteger("0");
	clientKey = new BigInteger("0");
	seed = new BigInteger("0");

	//Sophie Germain, finding p and q
	debug("Generating p and q values");
	while (po = true) {
		//create a random probable prime
		qprime = new BigInteger(1023, 3, rnd);
		//multiply by two and add one to get p value
		temp = two.multiply(qprime);
		pprime = temp.add(one);

		if (pprime.isProbablePrime(3))
			break;
	}

	//send the p prime value to client
	try{
		debug("sending the p value:");
		debug(pprime.toString());
		CryptoUtilities.send(pprime.toByteArray(),out);
	}
	catch (IOException e) {
	    System.out.println ("couldn't send value");
	    close();
	}

	//create the g value
	while (po = true){
		g = g.add(one);
		if (!g.modPow(qprime, pprime).equals(one)){
			break;
		}
	}

	//send the g value to Client
	try{
		debug("sending the g value: ");
		debug(g.toString());
		CryptoUtilities.send(g.toByteArray(),out);
	}
	catch (IOException e) {
	    System.out.println ("couldn't send value");
	    close();
	}
	

	//getting the random exponent b
	SecureRandom bval = new SecureRandom();
	b = new BigInteger(1024, bval);
	b = b.mod(pprime.subtract(one));

	//compute g^b (mod p)
	serverKey = g.modPow(b, pprime);

	//send value g^b (mod p) to the client
	try{
		debug("sending the g^b (mod p) value");
		debug(serverKey.toString());
		CryptoUtilities.send(serverKey.toByteArray(),out);
	}
	catch (IOException e) {
	    System.out.println ("couldn't send value");
	    close();
	}

	//get the clients key value
	try{
		debug("getting the g^a (mod p) value");
		clientTemp = CryptoUtilities.receive(in);
		clientKey = new BigInteger(clientTemp);
	}
	catch (IOException e) {
	    System.out.println ("couldn't get the value");
	    close();
	}

	//compute g^ab (mod p)
	seed = clientKey.modPow(b, pprime);
	debug("THE KEY:");
	debug(seed.toString());
	
	// compute key:  1st 16 bytes of SHA-1 hash of seed
	key = CryptoUtilities.key_from_seed(seed.toByteArray());
 	debug("Using key = " + CryptoUtilities.toHexString(key.getEncoded()));
   }
   /**
     *************************************************************************************************************************************************
     */


    /**
     * Encrypted file transfer
     * @return true if file transfer was successful
     */
    public boolean receiveFile() {
	debug("Starting File Transfer");

	// get the output file name
	String outfilename;
	try {
	    debug("Receiving output file name");
	    outfilename = new String(CryptoUtilities.receiveAndDecrypt(key,in));
	    debug("Got file name = " + outfilename);
	}
	catch (IOException e) {
	    System.out.println("Error receiving the output file name");
	    close();
	    return false;
	}

	System.out.println("Output file: " + outfilename);



	// get the file size
	int size;
	try {
	    debug("Receiving file size");
	    size = Integer.parseInt(new String(CryptoUtilities.receiveAndDecrypt(key,in)));	
	    debug("Got file size = " + size);
	}
	catch (IOException e) {
	    System.out.println("Error sending the file length");
	    close();
	    return false;

	}

	System.out.println("File size = " + size);



	// get the encrypted, integrity-protected file
	byte[] hashed_plaintext;
	try {
	    debug("Receiving and decrypting file with MAC appended");
	    hashed_plaintext = CryptoUtilities.receiveAndDecrypt(key,in);
	}
	catch (IOException e) {
	    System.out.println("Error receiving encrypted file");
	    close();
	    return false;
	}


	// check validity of MAC.  Write to the file if valid.
	debug("Checking MAC");
	boolean fileOK = false;
	if (CryptoUtilities.verify_hash(hashed_plaintext,key)) {
	    debug("Message digest OK.  Writing file.");
	    System.out.println("Message digest OK. Writing file");

	    // extract plaintext and output to file
	    byte[] plaintext = CryptoUtilities.extract_message(hashed_plaintext);

	    // writing file
	    FileOutputStream outfile = null;
	    try {
		outfile = new FileOutputStream(outfilename);
		outfile.write(plaintext,0,plaintext.length);
		outfile.close();
	    }
	    catch (IOException e) {
		System.out.println("Error writing decrypted file.");
		close();
		return false;
	    }
	    finally {
		try {
		    outfile.close();
		}
		catch (IOException e) {
		    System.out.println("Error closing output file.");
		    return false;
		}
	    }


	    fileOK = true;

	    // send acknowledgement to client
	    try {
		debug("Sending \"passed\" acknowledgement.");
		CryptoUtilities.encryptAndSend("Passed".getBytes(),key,out);
	    }
	    catch (IOException e) {
		System.out.println("Error sending passed acknowledgement.");
		close();
		return true;
	    }

	    System.out.println("File written successfully.");
	}
	else {
	    System.out.println("Integrity check failed.  File not written.");

	    try {
		debug("Sending \"Failed\" acknowledgement.");
		CryptoUtilities.encryptAndSend("Failed".getBytes(),key,out);
	    }
	    catch (IOException e) {
		System.out.println("Error sending failed acknowledgement.");
		close();
		return false;
	    }
	}

	close();
	return fileOK;
    }



    /**
     * Shuts down the socket connection
     */
    public void close() {
	// shutdown socket and input reader
	try {
	    sock.close();
	    if (in != null)
		in.close();
	    if (out != null)
		out.close();
	} 
	catch (IOException e) {
	    return;
	}	
		
    }



	
    /**
     * This is what the thread does as it executes.  Gets the encryption key,
     * receives a file from the client, and shuts down.
     */
    public void run ()
    {
	// open input and output streams for file transfer
	try {
	    in = new DataInputStream(sock.getInputStream());
	    out = new DataOutputStream(sock.getOutputStream());
	}
	catch (UnknownHostException e) {
	    System.out.println ("Unknown host error.");
	    close();
	    return;
	}
	catch (IOException e) {
	    System.out.println ("Could not create input and output streams.");
	    close();
	    return;
	}

	// get the encryption key
	getKey();

	// do file transfer
	receiveFile();

	// shut down the client and kill the server
	close();
	parent.killall();
    }
}
