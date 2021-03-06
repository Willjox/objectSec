import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Server {
	Crypto crypt;
	public static void main(String[] args) throws Exception {
		DatagramSocket serverSocket = new DatagramSocket(4000);
		while (true) {
			byte[] receive = new byte[1024];
			byte[] send = new byte[1024];
			DatagramPacket receivedPacket = new DatagramPacket(receive, receive.length);
			serverSocket.receive(receivedPacket);
			String receivedMessage = new String(receivedPacket.getData());
			System.out.println("RECEIVED: " + receivedMessage);
			InetAddress IPAddress = receivedPacket.getAddress();
			int port = receivedPacket.getPort();
			String capitalizedMessage = receivedMessage.toUpperCase();
			send = capitalizedMessage.getBytes();
			DatagramPacket sendPacket = new DatagramPacket(send, send.length, IPAddress, port);
			serverSocket.send(sendPacket);
		}

	}
 private byte[] handShakeG() {
	 return crypt.getG();
 }
 private byte[] handShakeP() {
	 return crypt.getP();
 }
 private byte[] handShakeKey() {
	 return crypt.sendSecret();
 }
 private byte[] encrypt(String plainText) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
	 return crypt.encrypt(plainText.getBytes());
 }
}
