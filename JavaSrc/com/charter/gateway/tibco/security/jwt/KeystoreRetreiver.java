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



public class KeystoreRetreiver {
	
	private KeyStore keyStore;
	
	private static KeystoreRetreiver instance= null;
	Logger logger = (Logger) LoggerFactory.getLogger(KeystoreRetreiver.class);
	
	private KeystoreRetreiver(String keystoreFilePath, String password,
			String keyStoreType) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException {
			keyStore = loadKeyStore(keystoreFilePath,password,keyStoreType);

	}
	
	private KeystoreRetreiver() {
		
	}
	
	public synchronized static KeystoreRetreiver getInstance (String keystoreFilePath, String password,
			String keyStoreType) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        if (instance == null) {
        	instance = new KeystoreRetreiver(keystoreFilePath, password,keyStoreType);
        }
	   return instance;
	}
	
	public KeyStore getKeyStore () {
		return keyStore;
	}
	
	public KeyStore loadKeyStore(String keystoreFilePath, String password,
			String keyStoreType) throws KeyStoreException, IOException,
			NoSuchAlgorithmException, CertificateException {
		if (null == keystoreFilePath) {
			throw new IllegalArgumentException("Keystore url may not be null");
		}
		File keystoreFile = new File(keystoreFilePath);
	    logger.debug("Initializing key store: {}", keystoreFilePath);
		FileInputStream is = new FileInputStream(keystoreFile);
		final KeyStore keystore = KeyStore.getInstance(keyStoreType);
		try {
			keystore.load(is, null == password ? null : password.toCharArray());
			System.out.println("Loaded key store");
		logger.debug("Loaded key store");
		} finally {
			if (null != is) {
				is.close();
			}
		}
		return keystore;
	}


}
