library jose_jwt.test.jwk.jwk_test;

import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jwk.dart';

/**
 * Tests the base JWK class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-02-04)
 */
//public class JWKTest extends TestCase {
main() {

  test('testMIMEType', () {

		expect("application/jwk+json; charset=UTF-8", JWK.MIME_TYPE);
  });

}

