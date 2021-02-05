package com.charter.gateway.tibco.security.jwt;

import java.io.IOException;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;

public class JsonWebTokenValidator {
	 
	public JsonWebTokenValidator(){
		
	}
	
	public String JWTValidator (String signedJWT, String audience,String CertificatePath, String CertificateIssuer) throws InvalidJwtException, IOException {
		
		JsonWebTokenProcessor jwtProcessor = new JsonWebTokenProcessor();
		String issuer = jwtProcessor.getIssuerFromJWS(signedJWT);
		JwtConsumer consumer = jwtProcessor.createConsumer(issuer, audience,  CertificatePath,  CertificateIssuer);
		JwtClaims jwtClaims = consumer.processToClaims(signedJWT);
		return jwtClaims.toJson();
	}

}
