package com.icicibank.apimgmt.service;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Service;
import com.icicibank.apimgmt.model.ResponseModel;

@Service
@Scope(value=ConfigurableBeanFactory.SCOPE_PROTOTYPE)
public interface TruliooApiService {

	public ResponseModel getRequestPacket() throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException,
			CertificateException, InvalidKeySpecException, IOException;

	public ResponseModel doEncryption(String input) throws NoSuchPaddingException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
			CertificateException, InvalidKeySpecException, IOException;

	public String doDecryption(String input)
			throws NoSuchAlgorithmException, NoSuchPaddingException, CertificateException, InvalidKeyException,
			IllegalBlockSizeException, InvalidKeySpecException, BadPaddingException, UnrecoverableKeyException,
			KeyStoreException, IOException, InvalidAlgorithmParameterException;

}
