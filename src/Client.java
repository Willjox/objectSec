import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;

class Client {

	public static void main(String[] args) throws Exception {
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		DatagramSocket clientSocket = new DatagramSocket();
		InetAddress IPAddress = InetAddress.getByName("localhost");
		while (true) {
			byte[] send = new byte[1024];
			byte receive[] = new byte[1024];
			String sendString = in.readLine();
			send = sendString.getBytes();
			DatagramPacket sendPacket = new DatagramPacket(send, send.length, IPAddress, 4000);
			clientSocket.send(sendPacket);
			DatagramPacket receivePacket = new DatagramPacket(receive, receive.length);
			clientSocket.receive(receivePacket);
			String receivedMessage = new String(receivePacket.getData());
			System.out.println("RECEIVED: " + receivedMessage);
		}
		// clientSocket.close();
	}

}
