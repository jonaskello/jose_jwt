library jose_jwt.test.jose.jose_object_handler_adapter_test;

import 'package:bignum/bignum.dart';
import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jose.dart';
import 'package:jose_jwt/src/crypto.dart';
import 'package:cipher/cipher.dart';
import 'package:cipher/impl/server.dart';

/**
 * Tests the JOSE object handler adapter.
 */
//public class JOSEObjectHandlerAdapterTest extends TestCase {
main() {

  initCipher();

  test('testParsePlainObject', () {

    PlainObject plainObject = new PlainObject.payloadOnly(new Payload.fromString("Hello world!"));

    expect(JOSEObject.parseWithHandler(plainObject.serialize(), new JOSEObjectHandlerAdapter<String>()), isNull);
  });


  test('testParseJWSObject', () {

    JWSObject jwsObject = new JWSObject(new JWSHeader.fromAlg(JWSAlgorithm.HS256), new Payload.fromString("Hello world!"));

    String key = "12345678901234567890123456789012";

    jwsObject.sign(new MACSigner.secretString(key));

    expect(JOSEObject.parseWithHandler(jwsObject.serialize(), new JOSEObjectHandlerAdapter<String>()), isNull);
  });


  test('testJWEObject', () {

    JWEObject jweObject = new JWEObject.toBeEncrypted(new JWEHeader.minimal(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM),
    new Payload.fromString("Hello world"));

//    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
//    keyGen.initialize(512);
//    var x = new SecureRandom("AES/CTR/PRNG");

//    var x = new SecureRandom("AES/CTR/PRNG");
    var x = new SecureRandom("AES/CTR/AUTO-SEED-PRNG");

    x.nextBigInteger(512);
    var keyGen = new KeyGenerator("RSA")
      ..init(new ParametersWithRandom(new RSAKeyGeneratorParameters(new BigInteger("65537"), 512, 12), new SecureRandom("AES/CTR/PRNG")));


    jweObject.encrypt(new RSAEncrypter(keyGen.generateKeyPair().publicKey as RSAPublicKey));

    expect(JOSEObject.parseWithHandler(jweObject.serialize(), new JOSEObjectHandlerAdapter<String>()), isNull);
  });

}

/*
 var rsapars = new RSAKeyGeneratorParameters(new BigInteger("65537"), 2048, 12);
    var params = new ParametersWithRandom(rsapars, new SecureRandom());

    var keyGenerator = new KeyGenerator("RSA")
      ..init( params )
    ;

    var keyPair = keyGenerator.generateKeyPair();

    outputKeyPair( keyPair );
 */