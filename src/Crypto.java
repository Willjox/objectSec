import java.math.BigInteger;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.agreement.DHAgreement;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.SecretKeySpec;
public class Crypto {
	DHParameters DHPara;
	BigInteger a;
	DHAgreement secretGen;
	DHKeyPairGenerator keyGen;
	AsymmetricCipherKeyPair keyPair;
	DHPrivateKeyParameters DHPrivKeyPara;
	DHPublicKeyParameters DHPubKeyPara;
	DHPrivateKey privKey;
	DHPublicKey pubKey;
	SecretKey secretKeySha1;
	SecretKey secretKeyAes;
	
	
	
	public  Crypto() { 
		DHParametersGenerator paraGen = new DHParametersGenerator();
		paraGen.init(1024, 1024, new SecureRandom());
		DHPara = paraGen.generateParameters();
		Security.addProvider(new BouncyCastleProvider());
		init();
	}
	
	public Crypto(BigInteger p ,BigInteger g) {
		DHPara = new DHParameters(p,g);
		init();	
	}
	
	private void init() {
		System.out.println("KEYGENasfFSAFAFafASFASFASFASFASF");
		DHKeyPairGenerator keyGen = new DHKeyPairGenerator();
		keyGen.init(new DHKeyGenerationParameters(new SecureRandom(), DHPara));
		keyPair = keyGen.generateKeyPair();
		//DHPubKeyPara = new DHPublicKeyParameters( pubKey.getY() ,DHPara);
		//DHPrivKeyPara = new DHPrivateKeyParameters(privKey.getX(),DHPara);
		DHPubKeyPara = (DHPublicKeyParameters) keyPair.getPublic();
		DHPrivKeyPara = (DHPrivateKeyParameters) keyPair.getPrivate();
		secretGen = new DHAgreement();
		secretGen.init(DHPrivKeyPara);
		
	}
	
	public byte[] getP() {
		return DHPara.getP().toByteArray();
	}
	public byte[] getG() {
		return DHPara.getG().toByteArray();
	}
	public byte[] sendSecret() {
		return secretGen.calculateMessage().toByteArray();
	}
	
	public void deriveKey(byte[] publicKey, byte[] message) {
		BigInteger intKey = new BigInteger(publicKey);
		BigInteger intMsg = new BigInteger(message);
		DHPublicKeyParameters pub = new DHPublicKeyParameters(intKey,DHPara);
		byte[] key = secretGen.calculateAgreement(pub, intMsg).toByteArray();
		byte[] derivedKey = new byte[16];
		for (int i = 0; i < 15; i++) {
			derivedKey[i] =  key[i];
		}
		secretKeySha1 =  new SecretKeySpec(derivedKey, 0, derivedKey.length, "Sha1");
		secretKeyAes =  new SecretKeySpec(derivedKey, 0, derivedKey.length, "AES");
		
	}
	
	public byte[] mac (byte[] plainText) throws NoSuchAlgorithmException, InvalidKeyException {
		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(secretKeySha1);
        mac.update(plainText);
        return mac.doFinal();
	}
	
	public byte[] encrypt(byte[] plainText) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKeyAes);
		byte[] encryptedText = cipher.doFinal(plainText);
		return encryptedText;
		
	}
	public byte[] decrypt(byte[] encryptedText) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secretKeyAes);
		byte[] plainText = cipher.doFinal(encryptedText);
		return plainText;
		
	}
}