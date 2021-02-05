package com.charter.gateway.tibco.security.jwt;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


//import ch.qos.logback.classic.Logger;



public class JWKProcessor {
	
	private JsonWebKey jsonWebKey = null;
	private static JWKProcessor instance= null;
	Logger logger = (Logger) LoggerFactory.getLogger(JWKProcessor.class);
	
	public JWKProcessor(String keystoreFilePath, String password,
			String keyStoreType,String alias) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
		PublicJsonWebKey myWebKey = null;
		try {
			
	
			KeyStore keyStore = KeystoreRetreiver.getInstance(keystoreFilePath, password, keyStoreType).getKeyStore();  
    		KeyPair keyPair = getKeyPair(keyStore,alias,password);
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
           
            myWebKey = PublicJsonWebKey.Factory.newPublicJwk(publicKey);
            myWebKey.setPrivateKey(privateKey);
			
		} catch (JoseException e) {
			// TODO Auto-generated catch block
		logger.error(e.getMessage());
		}
		jsonWebKey = myWebKey;
	}
	
	public JWKProcessor() {
		
	}

	
	public JsonWebKey getJsonWebKey () {
		return jsonWebKey;
	}
	
	
	public KeyPair getKeyPair(KeyStore keystore, String alias, String password)
			throws UnrecoverableKeyException, KeyStoreException,
			NoSuchAlgorithmException {
		Key key = (PrivateKey) keystore.getKey(alias, password.toCharArray());
		java.security.cert.Certificate cert = keystore.getCertificate(alias);
		PublicKey publicKey = cert.getPublicKey();
		return new KeyPair(publicKey, (PrivateKey) key);
	}
}
