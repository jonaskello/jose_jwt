library jose_jwt.test.jwk.key_type_test;

import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jose.dart';
import 'package:jose_jwt/src/jwk.dart';

/**
 * Tests the key type class.
 */
//public class KeyTypeTest extends TestCase {
main() {

  test('testConstants', () {

    expect("RSA", KeyType.RSA.getValue());
    expect(Requirement.REQUIRED, KeyType.RSA.getRequirement());

    expect("EC", KeyType.EC.getValue());
    expect(Requirement.RECOMMENDED, KeyType.EC.getRequirement());

    expect("oct", KeyType.OCT.getValue());
    expect(Requirement.OPTIONAL, KeyType.OCT.getRequirement());
  });

}

