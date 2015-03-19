library jose_jwt.test.jwt_handler_adapter_test;

import 'package:unittest/unittest.dart';
import 'package:cipher/cipher.dart';
import 'package:jose_jwt/src/jwt.dart';
import 'package:jose_jwt/src/jose.dart';
import 'package:jose_jwt/src/crypto.dart';

/**
 * Tests the JWT handler adapter.
 */
//public class JWTHandlerAdapterTest extends TestCase {

ReadOnlyJWTClaimsSet _generateClaimsSet() {

  JWTClaimsSet claimsSet = new JWTClaimsSet();
  claimsSet.setIssuer("c2id.com");
  claimsSet.setSubject("alice");
  return claimsSet;
}

main() {

  test('testParsePlainJWT', () {

    JWT plainJWT = new PlainJWT(_generateClaimsSet());

    expect(JWTParser.parseWithHandler(plainJWT.serialize(), new JWTHandlerAdapter<String>()), isNull);
  });

  test('testParseSignedJWT', () {

    SignedJWT signedJWT = new SignedJWT(new JWSHeader.fromAlg(JWSAlgorithm.HS256), _generateClaimsSet());

    String key = "12345678901234567890123456789012";

    signedJWT.sign(new MACSigner.secretString(key));

    expect(JWTParser.parseWithHandler(signedJWT.serialize(), new JWTHandlerAdapter<String>()), isNull);
  });

  test('testEncryptedJWT', () {

    EncryptedJWT encryptedJWT = new EncryptedJWT.toBeEncrypted(
        new JWEHeader.minimal(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM), _generateClaimsSet());

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(512);

    encryptedJWT.encrypt(new RSAEncrypter(keyGen.generateKeyPair().getPublic() as RSAPublicKey));

    expect(JWTParser.parseWithHandler(encryptedJWT.serialize(), new JWTHandlerAdapter<String>()), isNull);
  });

}
