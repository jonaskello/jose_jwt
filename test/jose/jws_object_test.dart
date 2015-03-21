library jose_jwt.test.jose.jws_object_test;

import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jose.dart';
import 'package:jose_jwt/src/util.dart';
import 'package:jose_jwt/src/crypto.dart';

/**
 * Tests JWS object methods.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-01-15)
 */
//public class JWSObjectTest extends TestCase {
main() {


  test('testBase64URLConstructor', () {

    JWSHeader header = new JWSHeader.fromAlg(JWSAlgorithm.RS256);

    Base64URL firstPart = header.toBase64URL();
    Base64URL secondPart = new Base64URL("abc");
    Base64URL thirdPart = new Base64URL("def");

    JWSObject jws = new JWSObject.fromParts(firstPart, secondPart, thirdPart);

    expect(firstPart, jws.getHeader().toBase64URL());
    expect(secondPart, jws.getPayload().toBase64URL());
    expect(thirdPart, jws.getSignature());

    expect(firstPart.toString() + ".abc.def", jws.serialize());
    expect(firstPart.toString() + ".abc.def", jws.getParsedString());

    expect(JWSObjectState.SIGNED, jws.getState());
  });


  test('testSignAndSerialize', () {

    JWSHeader header = new JWSHeader.fromAlg(JWSAlgorithm.HS256);

    JWSObject jwsObject = new JWSObject(header, new Payload.fromString("Hello world!"));

    Base64URL signingInput = Base64URL.encodeBytes(jwsObject.getSigningInput());

    expect(signingInput == Base64URL.encodeBytes(jwsObject.getSigningInput()), isTrue);

    jwsObject.sign(new MACSigner.secretString("12345678901234567890123456789012"));

    String output = jwsObject.serialize();

    expect(output, jwsObject.serialize());
  });

}
