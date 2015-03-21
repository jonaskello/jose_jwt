library jose_jwt.test.jose.jose_object_type_test;

import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jose.dart';

/**
 * Tests the JOSE object type header parmeter.
 */
//public class JOSEObjectTypeTest extends TestCase {
main() {

  test('testConstants', () {

    expect("JOSE", JOSEObjectType.JOSE.getType());
    expect("JOSE+JSON", JOSEObjectType.JOSE_JSON.getType());
    expect("JWT", JOSEObjectType.JWT.getType());
  });


  test('testToString', () {

    expect(JOSEObjectType.JOSE.getType(), JOSEObjectType.JOSE.toString());
    expect(JOSEObjectType.JOSE_JSON.getType(), JOSEObjectType.JOSE_JSON.toString());
    expect(JOSEObjectType.JWT.getType(), JOSEObjectType.JWT.toString());
  });


  test('testJSONAware', () {

    expect("\"JWT\"", JOSEObjectType.JWT.toJsonString());
  });

}
