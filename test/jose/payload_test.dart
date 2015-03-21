library jose_jwt.test.jose.payload_test;

import 'dart:convert';
import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jose.dart';
import 'package:jose_jwt/src/jwt.dart';

/**
 * Tests the JOSE payload class.
 */
//public class PayloadTest extends TestCase {
main() {

  test('testJWSObject', () {

    // From http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#appendix-A.1
    String s = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
    "." +
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
    "." +
    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    JWSObject jwsObject = JWSObject.parse(s);

    Payload payload = new Payload.fromJWSObject(jwsObject);

    expect(PayloadOrigin.JWS_OBJECT, payload.getOrigin());
    expect(jwsObject, payload.toJWSObject());
    expect(s, payload.toString());
    expect(s, UTF8.decode(payload.toBytes()));
  });


  test('testJWSObjectFromString', () {

    // From http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#appendix-A.1
    String s = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
    "." +
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
    "." +
    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    Payload payload = new Payload.fromString(s);

    expect(PayloadOrigin.STRING, payload.getOrigin());
    expect(JWSAlgorithm.HS256, payload.toJWSObject().getHeader().getAlgorithm());

    expect(s, payload.toString());
    expect(s, UTF8.decode(payload.toBytes()));
  });


  test('testSignedJWT', () {

    // From http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#appendix-A.1
    String s = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
    "." +
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
    "." +
    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    SignedJWT signedJWT = SignedJWT.parse(s);

    Payload payload = new Payload.fromSignedJwt(signedJWT);

    expect(PayloadOrigin.SIGNED_JWT, payload.getOrigin());
    expect(signedJWT, payload.toSignedJWT());

    expect(payload.toJWSObject(), isNotNull);

    expect(s, payload.toString());
    expect(s, UTF8.decode(payload.toBytes()));
  });

  test('testSignedJWTFromString', () {

    // From http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-31#appendix-A.1
    String s = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" +
    "." +
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
    "." +
    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    Payload payload = new Payload.fromString(s);

    expect(PayloadOrigin.STRING, payload.getOrigin());
    expect(JWSAlgorithm.HS256, payload.toJWSObject().getHeader().getAlgorithm());
    expect("joe", payload.toSignedJWT().getJWTClaimsSet().getIssuer());

    expect(payload.toJWSObject(), isNotNull);

    expect(s, payload.toString());
    expect(s, UTF8.decode(payload.toBytes()));
  });

  test('testRejectUnsignedJWS', () {

//		try {
    expect(() =>
    new Payload.fromJWSObject(new JWSObject(new JWSHeader.fromAlg(JWSAlgorithm.HS256), new Payload.fromString("test"))),
    throwsA(new isInstanceOf<ArgumentError>())
    );
//    fail();
//		} catch (IllegalArgumentException e) {
//			expect("The JWS object must be signed", e.getMessage());
//		}
  });

  test('testRejectUnsignedJWT', () {

//		try {
    expect(()=>
        new Payload.fromSignedJwt(new SignedJWT(new JWSHeader.fromAlg(JWSAlgorithm.HS256), new JWTClaimsSet())),
        throwsA(new isInstanceOf<ArgumentError>())
    );
//    fail();
//		} catch (IllegalArgumentException e) {
//			expect("The JWT must be signed", e.getMessage());
//		}
  });

/*
*/

}

