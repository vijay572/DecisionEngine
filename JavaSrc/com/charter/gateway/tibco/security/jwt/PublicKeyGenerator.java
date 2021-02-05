package com.charter.gateway.tibco.security.jwt;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;


import org.jose4j.keys.RsaKeyUtil;
import org.jose4j.lang.JoseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("unused")
public class PublicKeyGenerator {
	private PublicKey publicKey = null;
	private static PublicKeyGenerator instance= null;
	private String issuer = null;
	public static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
	public static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";
	private static final String CRLF = System.lineSeparator();
	
	Logger logger = (Logger) LoggerFactory.getLogger(PublicKeyGenerator.class);
	
	private PublicKeyGenerator(String CertificatePath, String issuer) throws IOException
	{
		PublicKey issuerPublicKey  = null;
		
			BufferedReader br = new BufferedReader(new FileReader(CertificatePath));
		    String line;
		    String strKeyPEM = "";
		    while ((line = br.readLine()) != null) {
		        strKeyPEM += line;
		        //logger.info(strKeyPEM);
		        logger.info("############### Certificate has been read ############");
		    }
		    br.close();
  
		    issuerPublicKey = createPublicKeyFromPEMEncodedString(strKeyPEM);
		this.issuer = issuer;	
		publicKey = issuerPublicKey;
	}
	
	private PublicKeyGenerator() {
		
	}
	
	public synchronized static PublicKeyGenerator getInstance (String CertificatePath, String issuer) throws IOException {
        if (instance == null) {
        	instance = new PublicKeyGenerator(CertificatePath,issuer);
        }
	   return instance;
	}
	
	public PublicKey getPublicKey () {
		return publicKey;
	}
	public PublicKey createPublicKeyFromPEMEncodedString(
			String publicKeyPEMEncodedString) {

		String formattedPublicKeyPEMEncodedString = String.format("%s%s%s%s%s",
				BEGIN_PUBLIC_KEY, CRLF, publicKeyPEMEncodedString, CRLF,
				END_PUBLIC_KEY);
		logger.info(formattedPublicKeyPEMEncodedString);
		RsaKeyUtil rsaKeyUtil = new RsaKeyUtil();
		PublicKey publickey;
		try {
			publickey = rsaKeyUtil.fromPemEncoded(formattedPublicKeyPEMEncodedString);
			return publickey;
		} catch (InvalidKeySpecException e) {
			logger.error(e.toString());
		} catch (JoseException e) {
			logger.error(e.toString());
		}
		return null;
	}

}
