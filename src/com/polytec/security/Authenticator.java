package com.polytec.security;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * The authenticator provides a authentication service. It handles requests from
 * the supplicant.
 */
public class Authenticator {

	private static final int AUTHENTICATION_SERVER_PORT = 1080;
	private static String arg;

	/*
	 * Starts the authenticationServer: open a server socket and launch a thread that
	 * will handle the requests when a connexion is received.
	 */
	public static void main(String args[]) {
		ServerSocket ss;
		try {
			if(args.length == 0 || !args[0].equals("TLS"))
				arg = "MD5";
			else 
				arg = args[0];

			System.out.println("Algorithm chosen: " + arg);
			ss = new ServerSocket(AUTHENTICATION_SERVER_PORT);
		} catch (IOException iox) {
			log("I/O error at server socket creation");
			iox.printStackTrace();
			return;
		}
		while (true) {
			Socket s = null;
			try {
				s = ss.accept();
				log("connection from" + s.getInetAddress());
				SupplicantHandler handler = new SupplicantHandler(s);
				new Thread(handler).start();
				
			} catch (IOException iox) {
				iox.printStackTrace();
			}
		}
	}

	/*
	 * A SupplicantHandler object is created for each connection to this authenticationServer by a Supplicant.
	 * It reads Frame objects from that supplicant and handles them appropriately.
	 */
	private static class SupplicantHandler implements Runnable {

		private ObjectOutputStream toClient;
		private ObjectInputStream fromClient;

		private SupplicantHandler(Socket socket) throws IOException {
			fromClient = new ObjectInputStream(socket.getInputStream());
			toClient = new ObjectOutputStream(socket.getOutputStream());
		}

		/*
		 * loops indefinitely reading objects from the socket
		 * and forwarding them to the handleFrame method
		 */
		public void run() {
			while (true) { // Change this to implement clean shutdown
				try {
					Object o = fromClient.readObject();
					log("received object " + o);
					Frame f = (Frame) o;
					if (f.code == Frame.CODE_INIT)
						handleFrame((Frame) o);
					else
						System.out.println("Buggy frame");
				} catch (IOException iox) {
					//most probably the authenticationServer closed the socket
					log("supplicant disconnected");
					return;
				} catch (Exception cnfx) {
					cnfx.printStackTrace();
				} 
			}
		}

		/*
		 * Sends a frame through the socket, to be read by the Supplicant
		 */
		private void sendFrame(Frame frame) {
			try {
//				System.out.println("Frame sent");
				toClient.reset();
				toClient.writeObject(frame);
				toClient.flush();
			} catch (IOException iox) {
				iox.printStackTrace();
			}
		}

		/*
		 * handles a frame received from the supplicant.
		 */
		private void handleFrame(Frame initFrame) throws Exception {

			
			// Authenticator sends Request:Identity (this is triggered by "init" message from supplicant)
			Data idData = new Data(Data.TYPE_IDENTITY, "Authenticator".getBytes());
			Frame authIDFrame = new Frame(Frame.CODE_REQUEST, (byte) ((initFrame.identifier + 1) % 128), idData);
			sendFrame(authIDFrame);
			
			// Authenticator receives Response:Identity (containing the public key of the supplicant)
			Frame supIDResponse = (Frame)fromClient.readObject();
			System.out.println(supIDResponse);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec kspec = new X509EncodedKeySpec(supIDResponse.data.data); 
			PublicKey supPubKey = kf.generatePublic(kspec);


			// Authenticator sends the Request:Challenge
			// It sends Request:MD5Challenge if the command line argument is MD5
			// It sends Request:TLSChallenge if the command line argument is TLS
			// It sends success or failure by checking that the hash or the decryption is consistent
			// The random string of the challenge is generated using a random method
			if(arg.equals("MD5"))
			{
				Data challengeData = new Data(Data.TYPE_MD5_CHALLENGE, new String("" + Math.random()*1000).getBytes());
				Frame challengeFrame = new Frame(Frame.CODE_REQUEST, (byte) ((supIDResponse.identifier + 1) % 128), challengeData);
				sendFrame(challengeFrame);
				
				Frame challengeResponse = (Frame)fromClient.readObject();
				System.out.println(challengeResponse);
				MessageDigest md = MessageDigest.getInstance("MD5");
				md.update(challengeData.data);
				byte hashed[] = md.digest();
				
				if(Arrays.equals(hashed, challengeResponse.data.data))
				{
					Data success = new Data(Data.TYPE_NOTIFICATION, "success".getBytes());
					Frame successFrame = new Frame(Frame.CODE_SUCCESS, (byte) ((challengeResponse.identifier + 1) % 128), success);
					sendFrame(successFrame);
				} else {
					Data failure = new Data(Data.TYPE_NOTIFICATION, "failure".getBytes());
					Frame failureFrame = new Frame(Frame.CODE_FAILURE, (byte) ((challengeResponse.identifier + 1) % 128), failure);
					sendFrame(failureFrame);
				}
			}
			else if(arg.equals("TLS"))
			{
				Data challengeData = new Data(Data.TYPE_TLS_CHALLENGE, new String("" + Math.random()*1000).getBytes());
				Frame challengeFrame = new Frame(Frame.CODE_REQUEST, (byte) ((supIDResponse.identifier + 1) % 128), challengeData);
				sendFrame(challengeFrame);
				
				Frame challengeResponse = (Frame)fromClient.readObject();
				System.out.println(challengeResponse);
				Cipher cipher = Cipher.getInstance("RSA");
				cipher.init(cipher.DECRYPT_MODE, supPubKey);
				byte deciphered[] = cipher.doFinal(challengeResponse.data.data);
				
				
				if(Arrays.equals(deciphered, challengeData.data))
				{
					Data success = new Data(Data.TYPE_NOTIFICATION, "success".getBytes());
					Frame successFrame = new Frame(Frame.CODE_SUCCESS, (byte) ((challengeResponse.identifier + 1) % 128), success);
					sendFrame(successFrame);
				} else {
					Data failure = new Data(Data.TYPE_NOTIFICATION, "failure".getBytes());
					Frame failureFrame = new Frame(Frame.CODE_FAILURE, (byte) ((challengeResponse.identifier + 1) % 128), failure);
					sendFrame(failureFrame);
				}
			}
			
		}
	}

	static void log(String s) {
		System.out.println(s);
	}
}