package com.icicibank.apimgmt.controller;

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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.icicibank.apimgmt.model.ResponseModel;
import com.icicibank.apimgmt.service.TruliooApiService;

@RestController
@RequestMapping(value="/api/v0")
@Scope(value=ConfigurableBeanFactory.SCOPE_PROTOTYPE)
public class TruliooApiController {

	@Autowired
	TruliooApiService service;
	
	@Autowired
	ResponseModel responseModel;
	
	Logger logger = LoggerFactory.getLogger(TruliooApiController.class);
	
	@GetMapping(value="/getRequestPacket",produces="application/json")
	public ResponseEntity<ResponseModel> getRequestPacket(){
		
		try {
			responseModel=service.getRequestPacket();
		} catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
				| CertificateException | InvalidKeySpecException | IOException e) {
			logger.info(e.getMessage());
			responseModel.setErrorMessage(e.getMessage());
		}
		return ResponseEntity.ok().body(responseModel);
	}
	
	@PostMapping(value="/getEcryptedData",produces="application/json")
	public ResponseEntity<ResponseModel> doEncryption(@RequestBody String input){
	
		try {
			responseModel=service.doEncryption(input);
		} catch (InvalidKeyException | NoSuchPaddingException | NoSuchAlgorithmException
				| InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException
				| CertificateException | InvalidKeySpecException | IOException e) {
			logger.info(e.getMessage());
			responseModel.setErrorMessage(e.getMessage());
		}
		
		return ResponseEntity.ok().body(responseModel);
	}
	
	@PostMapping(value="/getDecryptedData",produces="application/json")
	public ResponseEntity<String> doDecryption(@RequestBody String input){
		
		String responseModel="";
		try {
			responseModel=service.doDecryption(input);
		} catch (InvalidKeyException | UnrecoverableKeyException | NoSuchAlgorithmException | NoSuchPaddingException
				| CertificateException | IllegalBlockSizeException | InvalidKeySpecException | BadPaddingException
				| KeyStoreException | InvalidAlgorithmParameterException | IOException e) {
			logger.info(e.getMessage());
			e.printStackTrace();
			responseModel.concat(e.getMessage());
		}
		return ResponseEntity.ok().body(responseModel);
	}
}
