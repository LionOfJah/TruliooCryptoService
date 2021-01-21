package com.icicibank.apimgmt.service.impl;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;

import com.icicibank.apimgmt.model.ResponseModel;
import com.icicibank.apimgmt.service.TruliooApiService;
import com.icicibank.apimgmt.util.PemUtils;

@Service
@Scope(value = ConfigurableBeanFactory.SCOPE_PROTOTYPE)
public class TruliooApiServiceImpl implements TruliooApiService {

	static final String SYMM_CIPHER = "AES/CBC/PKCS5PADDING";
	static final String ASYMM_CIPHER = "RSA/ECB/PKCS1Padding";

	Logger logger = LoggerFactory.getLogger(TruliooApiServiceImpl.class);

	@Value("${app.publickey.path}")
	String publicKeyPath;

	@Value("${app.username}")
	String userName;

	@Value("${app.password}")
	String password;

	@Autowired
	PemUtils pemUtils;

	@Autowired
	ResponseModel responseModel;

	@Override
	public ResponseModel getRequestPacket() throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException,
			CertificateException, InvalidKeySpecException, IOException {

		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(256);
		SecretKey skey = kgen.generateKey();
		byte[] raw = skey.getEncoded();
		Cipher aesCipher = Cipher.getInstance(SYMM_CIPHER);
		SecureRandom randomSecureRandom = new SecureRandom();
		byte[] iv = new byte[aesCipher.getBlockSize()];
		randomSecureRandom.nextBytes(iv);
		IvParameterSpec ivParams = new IvParameterSpec(iv);
		aesCipher.init(Cipher.ENCRYPT_MODE, skey, ivParams);
		// byte[] encrypted = aesCipher.doFinal("Hello from Java".getBytes());

		byte[] encryptedUsername = aesCipher.doFinal(userName.getBytes());
		byte[] encryptedPassword = aesCipher.doFinal(password.getBytes());
		responseModel.setEncryptedUserName(Base64.getEncoder().encodeToString(encryptedUsername));
		responseModel.setEncryptedPassword(Base64.getEncoder().encodeToString(encryptedPassword));
		responseModel.setEncryptedData("");
		responseModel.setIv(Base64.getEncoder().encodeToString(iv));
		responseModel.setEncryptedKey(Base64.getEncoder().encodeToString(encryptAsymm(raw)));
		logger.info(" responseModel " + responseModel.toString());
		return responseModel;
	}

	@Override
	public ResponseModel doEncryption(String input) throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException,
			CertificateException, InvalidKeySpecException, IOException {
		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(256);
		SecretKey skey = kgen.generateKey();
		byte[] raw = skey.getEncoded();
		Cipher aesCipher = Cipher.getInstance(SYMM_CIPHER);
		SecureRandom randomSecureRandom = new SecureRandom();
		byte[] iv = new byte[aesCipher.getBlockSize()];
		randomSecureRandom.nextBytes(iv);
		IvParameterSpec ivParams = new IvParameterSpec(iv);
		aesCipher.init(Cipher.ENCRYPT_MODE, skey, ivParams);
		// byte[] encrypted = aesCipher.doFinal("Hello from Java".getBytes());

		byte[] encryptedUsername = aesCipher.doFinal(userName.getBytes());
		byte[] encryptedPassword = aesCipher.doFinal(password.getBytes());
		responseModel.setEncryptedUserName(Base64.getEncoder().encodeToString(encryptedUsername));
		responseModel.setEncryptedPassword(Base64.getEncoder().encodeToString(encryptedPassword));
		responseModel.setEncryptedData(Base64.getEncoder().encodeToString(aesCipher.doFinal(input.getBytes())));
		responseModel.setIv(Base64.getEncoder().encodeToString(iv));
		responseModel.setEncryptedKey(Base64.getEncoder().encodeToString(encryptAsymm(raw)));
		logger.info(" responseModel " + responseModel.toString());
		return responseModel;
	}

	@Override
	public String doDecryption(String input)
			throws NoSuchAlgorithmException, NoSuchPaddingException, CertificateException, InvalidKeyException,
			IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException, UnrecoverableKeyException,
			KeyStoreException, IOException, InvalidAlgorithmParameterException {

		JSONObject obj = new JSONObject(input);
		byte[] aesKeyBytes = decryptAsymm(obj.getString("encryptedKey"));
		SecretKeySpec skeySpec = new SecretKeySpec(aesKeyBytes, "AES");
		Cipher aesCipher = Cipher.getInstance(SYMM_CIPHER);
		IvParameterSpec ivPS = new IvParameterSpec(Base64.getDecoder().decode(obj.getString("iv")));
		aesCipher.init(Cipher.DECRYPT_MODE, skeySpec, ivPS);
		byte[] decodedValue = Base64.getDecoder().decode(obj.getString("encryptedData"));
		byte[] decValue = aesCipher.doFinal(decodedValue);
		String decryptedValue = new String(decValue);
		logger.info(" decrypted " + decryptedValue);
		return decryptedValue;
	}

	public byte[] encryptAsymm(byte[] bytes)
			throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, CertificateException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {

		// Key key = pemUtils.readPublicKeyFromFile(publicKeyPath, "RSA");

		byte[] pkcs1enc = Base64.getDecoder().decode(publicKeyPath); // extract
																																																					// PKCS1
																																																					// PKCS1
		AlgorithmIdentifier algid = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
		SubjectPublicKeyInfo spki2 = new SubjectPublicKeyInfo(algid, pkcs1enc);
		EncodedKeySpec publicSpec = new X509EncodedKeySpec(spki2.getEncoded());
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		Key key = keyFactory.generatePublic(publicSpec);

		Cipher cipher = Cipher.getInstance(ASYMM_CIPHER);
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte[] encryptedMsg = cipher.doFinal(bytes);
		return encryptedMsg;
	}

	public byte[] decryptAsymm(String b64EncryptedMsg) throws NoSuchAlgorithmException, NoSuchPaddingException,
			CertificateException, InvalidKeyException, IllegalBlockSizeException, InvalidKeySpecException,
			BadPaddingException, UnrecoverableKeyException, KeyStoreException, IOException {

		Cipher cipher = Cipher.getInstance(ASYMM_CIPHER);
		/*
		 * KeyFactory kf = KeyFactory.getInstance("RSA"); PKCS8EncodedKeySpec
		 * keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(""));
		 * byte[] encryptedMsg = Base64.getDecoder().decode(b64EncryptedMsg); Key key =
		 * kf.generatePrivate(keySpecPKCS8);
		 */

		byte[] encryptedMsg = Base64.getDecoder().decode(b64EncryptedMsg);
		Key key = PemUtils.readPrivateKeyFromFile( "RSA");
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte[] decryptedMsg = cipher.doFinal(encryptedMsg);
		return decryptedMsg;
	}

	public TruliooApiServiceImpl() {
		
	}
}
