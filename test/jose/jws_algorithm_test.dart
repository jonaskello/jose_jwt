library jose_jwt.test.jose.jws_algorithm_test;

import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jose.dart';

/**
 * Tests the JWS Algorithm class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-08-20)
 */
//public class JWSAlgorithmTest extends TestCase {
main() {

  test('testParse', () {

		expect(JWSAlgorithm.HS256, JWSAlgorithm.parse("HS256"));
		expect(JWSAlgorithm.HS384, JWSAlgorithm.parse("HS384"));
		expect(JWSAlgorithm.HS512, JWSAlgorithm.parse("HS512"));

		expect(JWSAlgorithm.RS256, JWSAlgorithm.parse("RS256"));
		expect(JWSAlgorithm.RS384, JWSAlgorithm.parse("RS384"));
		expect(JWSAlgorithm.RS512, JWSAlgorithm.parse("RS512"));

		expect(JWSAlgorithm.ES256, JWSAlgorithm.parse("ES256"));
		expect(JWSAlgorithm.ES384, JWSAlgorithm.parse("ES384"));
		expect(JWSAlgorithm.ES512, JWSAlgorithm.parse("ES512"));

		expect(JWSAlgorithm.PS256, JWSAlgorithm.parse("PS256"));
		expect(JWSAlgorithm.PS384, JWSAlgorithm.parse("PS384"));
		expect(JWSAlgorithm.PS512, JWSAlgorithm.parse("PS512"));
  });

}
