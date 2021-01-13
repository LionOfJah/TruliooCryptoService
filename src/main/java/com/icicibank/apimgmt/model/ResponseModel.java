package com.icicibank.apimgmt.model;

import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

@Component
@Scope(value=ConfigurableBeanFactory.SCOPE_PROTOTYPE)
public class ResponseModel {

	private String requestId;
	private String encryptedKey;
	private String iv;
	private String encryptedData;
	private String encryptedUserName;
	private String encryptedPassword;
	private String errorMessage;
	
	public ResponseModel() {
		
	}
	public String getRequestId() {
		return requestId;
	}
	public void setRequestId(String requestId) {
		this.requestId = requestId;
	}
	public String getEncryptedKey() {
		return encryptedKey;
	}
	public void setEncryptedKey(String encryptedKey) {
		this.encryptedKey = encryptedKey;
	}
	public String getIv() {
		return iv;
	}
	public void setIv(String iv) {
		this.iv = iv;
	}
	public String getEncryptedData() {
		return encryptedData;
	}
	public void setEncryptedData(String encryptedData) {
		this.encryptedData = encryptedData;
	}
	public String getEncryptedUserName() {
		return encryptedUserName;
	}
	public void setEncryptedUserName(String encryptedUserName) {
		this.encryptedUserName = encryptedUserName;
	}
	public String getEncryptedPassword() {
		return encryptedPassword;
	}
	public void setEncryptedPassword(String encryptedPassword) {
		this.encryptedPassword = encryptedPassword;
	}
	@Override
	public String toString() {
		return "ResponseModel [requestId=" + requestId + ", encryptedKey=" + encryptedKey + ", iv=" + iv
				+ ", encryptedData=" + encryptedData + ", encryptedUserName=" + encryptedUserName
				+ ", encryptedPassword=" + encryptedPassword + "]";
	}
	public String getErrorMessage() {
		return errorMessage;
	}
	public void setErrorMessage(String errorMessage) {
		this.errorMessage = errorMessage;
	}
	
	
	
	
}
