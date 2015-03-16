/*
/**
 * Tests the JWT handler adapter.
 */
public class JWTHandlerAdapterTest extends TestCase {


	private static ReadOnlyJWTClaimsSet generateClaimsSet() {

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setIssuer("c2id.com");
		claimsSet.setSubject("alice");
		return claimsSet;
	}


	public void testParsePlainJWT()
		throws Exception {

		JWT plainJWT = new PlainJWT(generateClaimsSet());

		assertNull(JWTParser.parse(plainJWT.serialize(), new JWTHandlerAdapter<String>()));
	}


	public void testParseSignedJWT()
		throws Exception {

		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), generateClaimsSet());

		String key = "12345678901234567890123456789012";

		signedJWT.sign(new MACSigner(key));

		assertNull(JWTParser.parse(signedJWT.serialize(), new JWTHandlerAdapter<String>()));
	}


	public void testEncryptedJWT()
		throws Exception {

		EncryptedJWT encryptedJWT = new EncryptedJWT(new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM), generateClaimsSet());

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);

		encryptedJWT.encrypt(new RSAEncrypter((RSAPublicKey)keyGen.generateKeyPair().getPublic()));

		assertNull(JWTParser.parse(encryptedJWT.serialize(), new JWTHandlerAdapter<String>()));
	}
}
*/
