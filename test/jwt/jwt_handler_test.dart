/*
/**
 * Tests the JWT handler interface.
 */
public class JWTHandlerTest extends TestCase {


	public static class JWTHandlerImpl implements JWTHandler<String> {


		@Override
		public String onPlainJWT(PlainJWT plainJWT) {
			return "plain";
		}


		@Override
		public String onSignedJWT(SignedJWT signedJWT) {
			return "signed";
		}


		@Override
		public String onEncryptedJWT(EncryptedJWT encryptedJWT) {
			return "encrypted";
		}
	}


	private static ReadOnlyJWTClaimsSet generateClaimsSet() {

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setIssuer("c2id.com");
		claimsSet.setSubject("alice");
		return claimsSet;
	}


	public void testParsePlainJWT()
		throws Exception {

		JWT plainJWT = new PlainJWT(generateClaimsSet());

		assertEquals("plain", JWTParser.parse(plainJWT.serialize(), new JWTHandlerImpl()));
	}


	public void testParseSignedJWT()
		throws Exception {

		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), generateClaimsSet());

		String key = "12345678901234567890123456789012";

		signedJWT.sign(new MACSigner(key));

		assertEquals("signed", JWTParser.parse(signedJWT.serialize(), new JWTHandlerImpl()));
	}


	public void testEncryptedJWT()
		throws Exception {

		EncryptedJWT encryptedJWT = new EncryptedJWT(new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM), generateClaimsSet());

		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(512);

		encryptedJWT.encrypt(new RSAEncrypter((RSAPublicKey)keyGen.generateKeyPair().getPublic()));

		assertEquals("encrypted", JWTParser.parse(encryptedJWT.serialize(), new JWTHandlerImpl()));
	}
}
*/
