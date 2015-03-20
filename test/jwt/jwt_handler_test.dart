library jose_jwt.test.jwt.jwt_handler_test;

import 'package:unittest/unittest.dart';
import 'package:cipher/cipher.dart';
import 'package:jose_jwt/src/jwt.dart';
import 'package:jose_jwt/src/jose.dart';
import 'package:jose_jwt/src/crypto.dart';

/**
 * Tests the JWT handler interface.
 */
//public class JWTHandlerTest extends TestCase {

ReadOnlyJWTClaimsSet _generateClaimsSet() {

  JWTClaimsSet claimsSet = new JWTClaimsSet();
  claimsSet.setIssuer("c2id.com");
  claimsSet.setSubject("alice");
  return claimsSet;
}

class JWTHandlerImpl implements JWTHandler<String> {

  @override
  String onPlainJWT(PlainJWT plainJWT) {
    return "plain";
  }


  @override
  String onSignedJWT(SignedJWT signedJWT) {
    return "signed";
  }

  @override
  String onEncryptedJWT(EncryptedJWT encryptedJWT) {
    return "encrypted";
  }
}

main() {

  test('testParsePlainJWT', () {

    JWT plainJWT = new PlainJWT(_generateClaimsSet());

    expect("plain", equals(JWTParser.parseWithHandler(plainJWT.serialize(), new JWTHandlerImpl())));
  });

  test('testParseSignedJWT', () {

    SignedJWT signedJWT = new SignedJWT(new JWSHeader.fromAlg(JWSAlgorithm.HS256), _generateClaimsSet());

    String key = "12345678901234567890123456789012";

    signedJWT.sign(new MACSigner.secretString(key));

    expect("signed", equals(JWTParser.parseWithHandler(signedJWT.serialize(), new JWTHandlerImpl())));
  });

  test('testEncryptedJWT', () {

    EncryptedJWT encryptedJWT = new EncryptedJWT.toBeEncrypted(
        new JWEHeader.minimal(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM), _generateClaimsSet());

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(512);

    encryptedJWT.encrypt(new RSAEncrypter(keyGen.generateKeyPair().getPublic() as RSAPublicKey));

    expect("encrypted", equals(JWTParser.parseWithHandler(encryptedJWT.serialize(), new JWTHandlerImpl())));
  });

}
