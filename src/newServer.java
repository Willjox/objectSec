import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.asn1.x9.DHPublicKey;

class newServer {

	public static void main(String[] args) throws Exception {
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		DatagramSocket clientSocket = new DatagramSocket();
		InetAddress IPAddress = InetAddress.getByName("localhost");
		while (true) {
			byte[] send;
			byte receive[] = new byte[6000];
			String sendString = in.readLine();
			send = sendString.getBytes();
			DatagramPacket sendPacket = new DatagramPacket(send, send.length, IPAddress, 4000);
			clientSocket.send(sendPacket);
			DatagramPacket receivePacket = new DatagramPacket(receive, receive.length);
			clientSocket.receive(receivePacket);
			String receivedMessage = new String(receivePacket.getData());
			System.out.println("RECEIVED: " + receivedMessage);
		}
		//clientSocket.close();
	}
	private void handshake(DatagramSocket socket, Crypto crypto, InetAddress IPAddress) throws IOException {
		byte[] data;
		//Send G parameter
		data = crypto.getG();
		DatagramPacket packet = new DatagramPacket(data, data.length,IPAddress,4000);
		socket.send(packet);
		//Send P parameter
		data = crypto.getP();
		packet = new DatagramPacket(data, data.length,IPAddress,4000);
		socket.send(packet);
		//Send Secret
		data = crypto.sendSecret();
		packet = new DatagramPacket(data, data.length,IPAddress,4000);
		socket.send(packet);
		//Recieve Client pubkey
		data = new byte[5120];
		packet = new DatagramPacket(data, data.length);
		socket.receive(packet);
		byte[] publicKey = packet.getData();
		//Receive and derive Secret
		packet = new DatagramPacket(data, data.length);
		socket.receive(packet);
		crypto.deriveKey(publicKey, packet.getData());
		return;
		
		
		
		
	}
	private void dataTransfer(DatagramSocket Socket, Crypto crypto) throws IOException {
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		System.out.println("Message: ");
		byte[] msg = in.readLine().getBytes(StandardCharsets.UTF_8);
		msg = crypto.encrypt(msg);
		byte[] mac = crypto.mac(msg);
		byte[] data = new byte[(mac.length + msg.length)];
		DatagramPacketpacket = new DatagramPacket(data, data.length,IPAddress,4000);
		
	}

}