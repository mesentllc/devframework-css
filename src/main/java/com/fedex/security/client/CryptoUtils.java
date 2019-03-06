package com.fedex.security.client;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CharsetEncoder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

public class CryptoUtils
		implements CryptoConstants {
	private static final Charset UTF8 = Charset.forName("UTF-8");

	public static String digest(byte[] plaintext, String type)
			throws CryptoException {
		try {
			MessageDigest md = MessageDigest.getInstance(type);
			byte[] digested = md.digest(plaintext);
			return new String(Hex.encodeHex(digested));
		}
		catch (NoSuchAlgorithmException nsae) {
			throw new CryptoException("Could not find digest type.", nsae);
		}
	}

	public static String pbe(char[] password, char[] plaintext, byte[] salt, int iterations)
			throws NoSuchAlgorithmException, IOException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		PBEKeySpec keySpec = new PBEKeySpec(password);
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithSHA1AndDESede");
		SecretKey key = keyFactory.generateSecret(keySpec);
		PBEParameterSpec paramSpec = new PBEParameterSpec(salt, iterations);
		Cipher cipher = Cipher.getInstance("PBEWithSHA1AndDESede");
		cipher.init(1, key, paramSpec);
		CharBuffer ptcb = CharBuffer.wrap(plaintext);
		CharsetEncoder utfEncoder = UTF8.newEncoder();
		byte[] plainbytes = utfEncoder.encode(ptcb).array();
		byte[] ciphertext = cipher.doFinal(plainbytes);
		String ciphertextString = Base64.encodeBytes(ciphertext);
		return ciphertextString;
	}

	public static String pbe(char[] password, char[] plaintext)
			throws CryptoException {
		try {
			SecureRandom sr = new SecureRandom();
			byte[] salt = {1, 2, 3, 4, 5, 6, 7, 8};
			sr.nextBytes(salt);
			String ciphertext = pbe(password, plaintext, salt, 2000);
			StringBuffer sbuf = new StringBuffer();
			sbuf.append(Hex.encodeHex(salt));
			sbuf.append(" ").append(ciphertext);
			return sbuf.toString();
		}
		catch (Throwable t) {
			throw new CryptoException("Unrecoverable error in PBE", t);
		}
	}

	public static String pbe(String password, String plaintext)
			throws CryptoException {
		return pbe(password.toCharArray(), plaintext.toCharArray());
	}

	public static char[] pbd(char[] password, String ciphertext, byte[] salt, int iterations)
			throws NoSuchAlgorithmException, IOException, InvalidKeyException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException, InvalidAlgorithmParameterException {
		PBEKeySpec keySpec = new PBEKeySpec(password);
		SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBEWithSHA1AndDESede");
		SecretKey key = keyFactory.generateSecret(keySpec);
		PBEParameterSpec paramSpec = new PBEParameterSpec(salt, iterations);
		Cipher cipher = Cipher.getInstance("PBEWithSHA1AndDESede");
		cipher.init(2, key, paramSpec);
		byte[] unencodedciphertext = Base64.decode(ciphertext);
		byte[] plaintext = cipher.doFinal(unencodedciphertext);
		ByteBuffer ptbb = ByteBuffer.wrap(plaintext);
		CharsetDecoder utfDecoder = UTF8.newDecoder();
		CharBuffer ptcb = utfDecoder.decode(ptbb);
		return ptcb.array();
	}

	public static char[] pbd(char[] password, String ciphertext)
			throws CryptoException {
		try {
			String[] strings = ciphertext.split(" ");
			byte[] salt = null;
			try {
				salt = Hex.decodeHex(strings[0].toCharArray());
			}
			catch (DecoderException de) {
				throw new RuntimeException("PBE decryption failed, salt corrupted.", de);
			}
			String b64encoded = strings[1];
			return pbd(password, b64encoded, salt, 2000);
		}
		catch (Throwable t) {
			throw new CryptoException("Unrecoverable error in PBE decryption", t);
		}
	}

	public static String pbd(String password, String ciphertext)
			throws CryptoException {
		return new String(pbd(password.toCharArray(), ciphertext));
	}

	public static byte[] convert(char[] src) {
		try {
			CharBuffer cb = CharBuffer.wrap(src);
			CharsetEncoder utfEncoder = UTF8.newEncoder();
			return utfEncoder.encode(cb).array();
		}
		catch (CharacterCodingException ce) {
		}
		return null;
	}

	public static char[] convert(byte[] src) {
		try {
			ByteBuffer bb = ByteBuffer.wrap(src);
			CharsetDecoder utfDecoder = UTF8.newDecoder();
			return utfDecoder.decode(bb).array();
		}
		catch (CharacterCodingException ce) {
		}
		return null;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\client\CryptoUtils.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */