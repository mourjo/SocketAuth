package com.polytec.security;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Supplicant {

	private static final String DEFAULT_AUTHENTICATION_SERVER_HOST = "localhost";
	private static final int DEFAULT_authenticationServer_PORT = 1080;
	
	private ObjectInputStream fromServer;
	private ObjectOutputStream toServer;
	
	private PublicKey publicKey;
	private PrivateKey privateKey;

	public void connect(String authenticationServerHost, int authenticationServerPort) {
		try {
			Socket socket = new Socket(authenticationServerHost, authenticationServerPort);
			toServer = new ObjectOutputStream(socket.getOutputStream());
			fromServer = new ObjectInputStream(socket.getInputStream());
		} catch (UnknownHostException uhx) {
			uhx.printStackTrace();
		} catch (IOException iox) {
			iox.printStackTrace();
		}
	}

	/*
	 * connects to an authenticationServer and authenticates to it.
	 */
	public void authenticate() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

		// We send an init message to trigger the authentication process
		Frame init = new Frame(Frame.CODE_INIT, (byte)((Math.random()*1000)%128), new Data((byte)0, "init".getBytes()) );
		sendFrame(init);
		
		// Supplicant receives the Request:Identity from authenticator
		Frame authReqFrame = readFrame();
		System.out.println(authReqFrame);
		
		// Supplicant sends Response:Identity to authenticator
		// It always contains the public key of the supplicant
		Data idData = new Data(Data.TYPE_IDENTITY, publicKey.getEncoded());
		Frame idResponseFrame = new Frame(Frame.CODE_RESPONSE, authReqFrame.identifier, idData);
		sendFrame(idResponseFrame);
		
		// Supplicant receives the Request:Challenge
		// Depending on the type of challenge, it hashes or encrypts the data with its private key
		// And sends it
		Frame challengeFrame = readFrame();
		System.out.println(challengeFrame);
		byte challengeData[] = challengeFrame.data.data;
		if(challengeFrame.data.type == Data.TYPE_MD5_CHALLENGE)
		{
			MessageDigest md = MessageDigest.getInstance("MD5");
			md.update(challengeData);
		
			Data hashedData = new Data(Data.TYPE_MD5_CHALLENGE, md.digest());
			Frame hashedFrame = new Frame(Frame.CODE_RESPONSE, challengeFrame.identifier, hashedData);
			sendFrame(hashedFrame);
		}
		else if (challengeFrame.data.type == Data.TYPE_TLS_CHALLENGE)
		{
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(cipher.ENCRYPT_MODE, privateKey);
			Data encryptedData = new Data(Data.TYPE_TLS_CHALLENGE, cipher.doFinal(challengeData));
			Frame hashedFrame = new Frame(Frame.CODE_RESPONSE, challengeFrame.identifier, encryptedData);
			sendFrame(hashedFrame);
		}
		
		// Supplicant receives the success/failure frame, and displays the result
		Frame resultFrame = readFrame();
		System.out.println(resultFrame);
		if(resultFrame.code == Frame.CODE_SUCCESS)
			System.out.println("Success!");
		else
			System.out.println("Failure");
		
	}

	private void sendFrame(Frame frame) {
		try {
			toServer.writeObject(frame);
		} catch (IOException iox){
			iox.printStackTrace();
		}
	}

	/*
	 * blocks until a frame is read from the authenticationServer, then return that frame
	 */
	private Frame readFrame() {
		try {
			return (Frame) fromServer.readObject();
		} catch (IOException iox) {
			iox.printStackTrace();
		} catch (ClassNotFoundException cnfx) {
			cnfx.printStackTrace();
		}
		return null;
	}
	
	public Supplicant()
	{
		KeyPairGenerator keygen;
		try {
		
			keygen = KeyPairGenerator.getInstance("RSA");
			keygen.initialize(1024);
			KeyPair keypair = keygen.genKeyPair();
			// save the public/private key
			publicKey = keypair.getPublic();
			privateKey = keypair.getPrivate();

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public static void main(String argv[]) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		Supplicant supplicant = new Supplicant();
		supplicant.connect(DEFAULT_AUTHENTICATION_SERVER_HOST , 
						   DEFAULT_authenticationServer_PORT);
		supplicant.authenticate();
	}
}