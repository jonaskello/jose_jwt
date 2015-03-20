library jose_jwt.test.jose.jose_object_handler_test;

import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jose.dart';
import 'package:jose_jwt/src/crypto.dart';

/**
 * Tests the JOSE object handler interface.
 */
//public class JOSEObjectHandlerTest extends TestCase {

class JOSEObjectHandlerImpl implements JOSEObjectHandler<String> {

  @override
  String onPlainObject(PlainObject plainObject) {
    return "plain";
  }

  @override
  String onJWSObject(JWSObject jwsObject) {
    return "jws";
  }

  @override
  String onJWEObject(JWEObject jweObject) {
    return "jwe";
  }
}


main() {

  test('testParsePlainObject', () {

    PlainObject plainObject = new PlainObject.payloadOnly(new Payload.fromString("Hello world!"));

    expect("plain", JOSEObject.parseWithHandler(plainObject.serialize(), new JOSEObjectHandlerImpl()));
  });

  test('testParseJWSObject', () {

    JWSObject jwsObject = new JWSObject(new JWSHeader.fromAlg(JWSAlgorithm.HS256), new Payload.fromString("Hello world!"));

    String key = "12345678901234567890123456789012";

    jwsObject.sign(new MACSigner.secretString(key));

    expect("jws", JOSEObject.parseWithHandler(jwsObject.serialize(), new JOSEObjectHandlerImpl()));
  });

  test('testJWEObject', () {

    JWEObject jweObject = new JWEObject.toBeEncrypted(new JWEHeader.minimal(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM),
    new Payload.fromString("Hello world"));

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(512);

    jweObject.encrypt(new RSAEncrypter(keyGen.generateKeyPair().getPublic()) as RSAPublicKey);

    expect("jwe", JOSEObject.parseWithHandler(jweObject.serialize(), new JOSEObjectHandlerImpl()));
  });

}
