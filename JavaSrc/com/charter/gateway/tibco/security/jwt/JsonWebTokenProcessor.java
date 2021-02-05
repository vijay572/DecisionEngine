package com.charter.gateway.tibco.security.jwt;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.jose4j.base64url.Base64;
import org.jose4j.jwk.PublicJsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;
import org.jose4j.keys.RsaKeyUtil;
import org.jose4j.lang.JoseException;

import com.tibco.be.model.functions.BEFunction;
import com.tibco.be.model.functions.BEPackage;

import javax.xml.bind.DatatypeConverter;

//import ch.qos.logback.classic.Logger;

@BEPackage(catalog="JWT", category = "functions")
public class JsonWebTokenProcessor {

	public static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
	public static final String END_PUBLIC_KEY = "-----END PUBLIC KEY-----";
	private static final String CRLF = System.lineSeparator();
	private static final String BEGIN_RSA_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----";
	private static final String END_RSA_PRIVATE_KEY = "-----END PRIVATE KEY-----";
	private static final String BEGIN_RSA_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----";
	private static final String END_RSA_PUBLIC_KEY = "-----END PUBLIC KEY-----";
	private static final String RSA = "RSA";
	private static final String JSON_WEB_KEY_ID = "00000000-0000-0000-0000-000000000000";
	public static final String BASE_CONFIG_DOMAIN = "api.corp.chartercom.com";
	public static final String CONFIG_DOMAIN_CLAIM_NAME= "config.domain";
	public static final String ORIGIN_CLAIMS_CLAIM_NAME = "security.oclaims";

//	Logger logger = (Logger) LoggerFactory.getLogger(JsonWebTokenProcessor.class);

	public String getIssuerFromJWS(String jws) {

		JwtConsumer consumer = new JwtConsumerBuilder().setSkipAllValidators()
				.setSkipSignatureVerification().build();
		try {
			JwtClaims unvalidatedClaims = consumer.processToClaims(jws);
			return unvalidatedClaims.getIssuer();
		} catch (InvalidJwtException | MalformedClaimException e) {
			// TODO Auto-generated catch block
			//logger.error(e.toString());
		}
		return null;

	}

	public JwtConsumer createConsumer(String issuer, String audience,
			String CertificatePath, String CertificateIssuer) throws IOException {
		PublicKey publicKey = PublicKeyGenerator.getInstance(CertificatePath, CertificateIssuer).getPublicKey();

		JwtConsumer consumer = new JwtConsumerBuilder()
				.setExpectedAudience(audience)
				.setExpectedIssuer(issuer)
				.setVerificationKey(publicKey)
				.setRequireSubject().build();
		return consumer;

	}

	public PublicKey createPublicKeyFromPEMEncodedString(
			String publicKeyPEMEncodedString) {

		String formattedPublicKeyPEMEncodedString = String.format("%s%s%s%s%s",
				BEGIN_PUBLIC_KEY, CRLF, publicKeyPEMEncodedString, CRLF,
				END_PUBLIC_KEY);
		RsaKeyUtil rsaKeyUtil = new RsaKeyUtil();
		PublicKey publickey;
		try {
			publickey = rsaKeyUtil
					.fromPemEncoded(formattedPublicKeyPEMEncodedString);
			return publickey;
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			//logger.error(e.toString());
		} catch (JoseException e) {
			// TODO Auto-generated catch block
			//logger.error(e.toString());
		}
		return null;
	}

	@SuppressWarnings("null")
	public static JwtClaims createJsonWebTokenClaims(String issuer, String audience,
			Long expiresInMinutes, String userId, 
			String originalClaims) throws InvalidJwtException {

		if (expiresInMinutes == null) {
			expiresInMinutes = 10L;
		}
		String originClaims = null;
		
//		if ( originalClaims !=null || (!originalClaims.isEmpty() && originalClaims.length()>0)){
//		JwtClaims originalJwtClaims = JwtClaims.parse(originalClaims);
//		originClaims=((String) originalJwtClaims.getClaimValue(ORIGIN_CLAIMS_CLAIM_NAME));
//
//		}
		// Create the Claims, which will be the content of the JWT
		JwtClaims claims = new JwtClaims();
		claims.setIssuer(issuer); // who creates the token and signs it
		claims.setAudience(audience); // to whom the token is intended to b sent
		claims.setExpirationTimeMinutesInTheFuture(expiresInMinutes); // time when token will expire

		claims.setGeneratedJwtId(); // a unique identifier for the token
		claims.setIssuedAtToNow(); // when the token was issued/created (now)
		claims.setNotBeforeMinutesInThePast(1); // time before which the token
												// is not yet valid (2 minutes
												// ago)
		claims.setSubject(userId);// the subject/principal is whom the token is
									// about
		claims.setStringClaim(CONFIG_DOMAIN_CLAIM_NAME,BASE_CONFIG_DOMAIN);
		if (originClaims!=null){
		claims.setStringClaim(ORIGIN_CLAIMS_CLAIM_NAME,  originClaims); // Setting
		}															// Origin// Claims
		//logger.debug(claims.toJson());
		return claims;
	}
	
	@BEFunction(name = "CreateJwt", params = {@com.tibco.be.model.functions.FunctionParamDescriptor(name = "keystoreFilePath", type = "string", desc = "Keystore FilePath"),
			@com.tibco.be.model.functions.FunctionParamDescriptor(name = "password", type = "string", desc = "password"), 
			@com.tibco.be.model.functions.FunctionParamDescriptor(name = "keyStoreType", type = "string", desc = "Keystore Type"),
			@com.tibco.be.model.functions.FunctionParamDescriptor(name = "alias", type = "string", desc = "alias"),
			@com.tibco.be.model.functions.FunctionParamDescriptor(name = "issuer", type = "string", desc = "issuer"),
			@com.tibco.be.model.functions.FunctionParamDescriptor(name = "audience", type = "string", desc = "audience"),
			@com.tibco.be.model.functions.FunctionParamDescriptor(name = "expiresInMinutes", type = "long", desc = "Expiry in minutes"),
			@com.tibco.be.model.functions.FunctionParamDescriptor(name = "userId", type = "string", desc = "user Id"),
			@com.tibco.be.model.functions.FunctionParamDescriptor(name = "originalClaims", type = "string", desc = "Original claims")
	})

	public static String createJsonWebSignature(String keystoreFilePath, String password, String keyStoreType,String alias,
			String issuer, String audience,
			Long expiresInMinutes, String userId, 
			String originalClaims) throws JoseException, InvalidJwtException, UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		//PublicJsonWebKey jwk = PublicJsonWebKey.Factory.newPublicJwk(jsonWebKey);
		JWKProcessor jwkProcessor = new JWKProcessor(keystoreFilePath, password, keyStoreType, alias);
		PublicJsonWebKey jwk =  (PublicJsonWebKey) jwkProcessor.getJsonWebKey();
		jwk.setKeyId(JSON_WEB_KEY_ID);
		//jwk.setPrivateKey(keyPair.getPrivate());
		jwk.setAlgorithm("RS256");
		JwtClaims claims = createJsonWebTokenClaims(issuer,audience,expiresInMinutes,userId,originalClaims);
		JsonWebSignature jws = new JsonWebSignature();
		jws.setPayload(claims.toJson());
		jws.setKey(jwk.getPrivateKey());
		jws.setKeyIdHeaderValue(jwk.getKeyId());
		jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.RSA_USING_SHA256);
		return jws.getCompactSerialization();
	}

	public PrivateKey PrivateKeyFromPemEncoded(String pem)
			throws InvalidKeySpecException, IOException,
			NoSuchAlgorithmException, NoSuchProviderException {

		int beginIndex = pem.indexOf(BEGIN_RSA_PRIVATE_KEY)
				+ BEGIN_RSA_PRIVATE_KEY.length();
		int endIndex = pem.indexOf(END_RSA_PRIVATE_KEY);
		String base64PrivateKey = pem.substring(beginIndex, endIndex).trim();

		// Generate KeyPair.
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
				Base64.decode(base64PrivateKey));
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

		return privateKey;
	}

	public PublicKey publicKeyFromPemEncoded(String pem)
			throws InvalidKeySpecException, IOException,
			NoSuchAlgorithmException, NoSuchProviderException {
		int beginIndex = pem.indexOf(BEGIN_RSA_PUBLIC_KEY)
				+ BEGIN_RSA_PUBLIC_KEY.length();
		int endIndex = pem.indexOf(END_RSA_PUBLIC_KEY);
		String base64 = pem.substring(beginIndex, endIndex).trim();

		byte[] decode = DatatypeConverter.parseBase64Binary(base64);

		X509EncodedKeySpec spec = new X509EncodedKeySpec(decode);

		KeyFactory keyFactory = KeyFactory.getInstance(RSA);
		return keyFactory.generatePublic(spec);
	}

	public KeyPair keyPairFromPemEncoded(String pem)
			throws InvalidKeySpecException, IOException,
			NoSuchAlgorithmException, NoSuchProviderException {
		PublicKey publicKey = publicKeyFromPemEncoded(pem);

		int beginIndex = pem.indexOf(BEGIN_RSA_PRIVATE_KEY)
				+ BEGIN_RSA_PRIVATE_KEY.length();
		int endIndex = pem.indexOf(END_RSA_PRIVATE_KEY);
		String base64PrivateKey = pem.substring(beginIndex, endIndex).trim();

		// Generate KeyPair.
		KeyFactory keyFactory = KeyFactory.getInstance(RSA);
		PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
				DatatypeConverter.parseBase64Binary(base64PrivateKey));
		PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

		return new KeyPair(publicKey, privateKey);
	}

	
//	public static PublicJsonWebKey createJwk(String keystoreFilePath, String password, String keyStoreType,String alias) throws Exception {
//
//		PublicJsonWebKey jwk =  (PublicJsonWebKey) JWKProcessor.getInstance(keystoreFilePath, password, keyStoreType, alias).getJsonWebKey();
//		jwk.setKeyId(JSON_WEB_KEY_ID);
//		//jwk.setPrivateKey(keyPair.getPrivate());
//		jwk.setAlgorithm("RS256");
//		return jwk;
//	}

	public KeyStore loadKeyStore(String keystoreFilePath, String password,
			String keyStoreType) throws KeyStoreException, IOException,
			NoSuchAlgorithmException, CertificateException {
		if (null == keystoreFilePath) {
			throw new IllegalArgumentException("Keystore url may not be null");
		}
		File keystoreFile = new File(keystoreFilePath);
		//logger.debug("Initializing key store: {}", keystoreFilePath);
		FileInputStream is = new FileInputStream(keystoreFile);
		final KeyStore keystore = KeyStore.getInstance(keyStoreType);
		try {
			keystore.load(is, null == password ? null : password.toCharArray());
			//logger.debug("Loaded key store");
		} finally {
			if (null != is) {
				is.close();
			}
		}
		return keystore;
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
