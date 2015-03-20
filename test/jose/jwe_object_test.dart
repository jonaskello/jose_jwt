library jose_jwt.test.jose.jwe_object_test;

import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jose.dart';
import 'package:jose_jwt/src/util.dart';

/**
 * Tests JWE object methods.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-08-20)
 */
//public class JWEObjectTest extends TestCase {
main() {

  test('testBase64URLConstructor', () {

		JWEHeader header = new JWEHeader.minimal(JWEAlgorithm.RSA1_5,
			                         EncryptionMethod.A128CBC_HS256);

		Base64URL firstPart = header.toBase64URL();
		Base64URL secondPart = new Base64URL("abc");
		Base64URL thirdPart = new Base64URL("def");
		Base64URL fourthPart = new Base64URL("ghi");
		Base64URL fifthPart = new Base64URL("jkl");

		JWEObject jwe = new JWEObject(firstPart, secondPart,
				thirdPart, fourthPart, 
				fifthPart);

		expect(firstPart, jwe.getHeader().toBase64URL());
		expect(secondPart, jwe.getEncryptedKey());
		expect(thirdPart, jwe.getIV());
		expect(fourthPart, jwe.getCipherText());

		expect(firstPart.toString() + ".abc.def.ghi.jkl", jwe.serialize());
		expect(firstPart.toString() + ".abc.def.ghi.jkl", jwe.getParsedString());

		expect(JWEObjectState.ENCRYPTED, jwe.getState());
  });

}
