import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class test {
	public static void main(String[] args) throws Exception {
		String p;
		String g;
		String text = new String("HEJSAN");
		String cryptText;
		String mac;
		String decryptText;
		BigInteger message;
		Security.addProvider(new BouncyCastleProvider());
		
		Crypto crypt = new Crypto();
		message = new BigInteger(crypt.sendSecret());
		g = new String(crypt.getG(), StandardCharsets.UTF_8);
		p = new String(crypt.getP(), StandardCharsets.UTF_8);
		crypt.deriveKey(crypt.DHPubKeyPara.getY().toByteArray(),message );
		cryptText = new String(crypt.encrypt(text.getBytes()), StandardCharsets.UTF_8);
		decryptText = new String(crypt.decrypt(crypt.encrypt(text.getBytes())), StandardCharsets.UTF_8);
		System.out.println(g);
		System.out.println(p);
		System.out.println(cryptText);
		System.out.println(decryptText);
		

	}
}
