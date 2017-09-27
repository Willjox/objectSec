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

	public void main(String[] args) throws Exception {
		DatagramSocket socket = new DatagramSocket();
		InetAddress IPAddress = InetAddress.getByName("localhost");
		Crypto crypto = new Crypto();
		while (true) {
			handshake(socket,crypto,IPAddress);
			dataTransfer(socket,crypto,IPAddress);
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
		//send pubKey
		data = crypto.getPub();
		packet = new DatagramPacket(data, data.length,IPAddress,4000);
		socket.send(packet);
		//Send Secret
		data = crypto.sendSecret();
		packet = new DatagramPacket(data, data.length,IPAddress,4000);
		socket.send(packet);
		//Receive Client pubkey
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
	private void dataTransfer(DatagramSocket socket, Crypto crypto, InetAddress IPAddress) throws IOException {
		//Read Msg and  to be sent convert to byte array
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		System.out.println("Message: ");
		byte[] msg = in.readLine().getBytes(StandardCharsets.UTF_8);
		//make room for timestamp
		byte[] crypt = new byte[msg.length + 1];
		for(int i = 1; i < msg.length + 2; i++ ) {
			crypt[i] = msg[i - 1 ];
		}
		Long time = new Long(System.currentTimeMillis());
		byte byteTime = time.byteValue();¨
		//insert time stamp and encrypt result
		crypt[0] = byteTime;
		crypt = crypto.encrypt(crypt);
		//Create MAC
		byte[] mac = crypto.mac(crypt);
		//new byte array, insert MAC bytes to first X
		byte[] data = new byte[(mac.length + crypt.length)];
		for(int i = 0; i < mac.length; i++ ) {
			data[i] = mac[i];
		}
		//Fill up the rest of the array with the encrypted data
		for(int i = 0; i < crypt.length; i++ ) {
			data[i + (mac.length - 1)] = crypt[i];
		}
		//send result
		DatagramPacket packet = new DatagramPacket(data, data.length,IPAddress,4000);
		socket.send(packet);
		return;
	}
}