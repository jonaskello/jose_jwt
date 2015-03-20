library jose_jwt.test.jose.jwe_algorithm_test;

import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jose.dart';

/**
 * Tests the JWS Algorithm class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-08-20)
 */
//public class JWEAlgorithmTest extends TestCase {
main() {

  test('testParse', () {

		expect(JWEAlgorithm.RSA1_5, JWEAlgorithm.parse("RSA1_5"));
		expect(JWEAlgorithm.RSA_OAEP, JWEAlgorithm.parse("RSA-OAEP"));

		expect(JWEAlgorithm.A128KW, JWEAlgorithm.parse("A128KW"));
		expect(JWEAlgorithm.A192KW, JWEAlgorithm.parse("A192KW"));
		expect(JWEAlgorithm.A256KW, JWEAlgorithm.parse("A256KW"));

		expect(JWEAlgorithm.DIR, JWEAlgorithm.parse("dir"));

		expect(JWEAlgorithm.ECDH_ES, JWEAlgorithm.parse("ECDH-ES"));

		expect(JWEAlgorithm.ECDH_ES_A128KW, JWEAlgorithm.parse("ECDH-ES+A128KW"));
		expect(JWEAlgorithm.ECDH_ES_A192KW, JWEAlgorithm.parse("ECDH-ES+A192KW"));
		expect(JWEAlgorithm.ECDH_ES_A256KW, JWEAlgorithm.parse("ECDH-ES+A256KW"));

		expect(JWEAlgorithm.A128GCMKW, JWEAlgorithm.parse("A128GCMKW"));
		expect(JWEAlgorithm.A192GCMKW, JWEAlgorithm.parse("A192GCMKW"));
		expect(JWEAlgorithm.A256GCMKW, JWEAlgorithm.parse("A256GCMKW"));

		expect(JWEAlgorithm.PBES2_HS256_A128KW, JWEAlgorithm.parse("PBES2-HS256+A128KW"));
		expect(JWEAlgorithm.PBES2_HS256_A192KW, JWEAlgorithm.parse("PBES2-HS256+A192KW"));
		expect(JWEAlgorithm.PBES2_HS256_A256KW, JWEAlgorithm.parse("PBES2-HS256+A256KW"));
  });

}
