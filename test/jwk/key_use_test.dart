library jose_jwt.test.jwk.key_use_test;

import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jwk.dart';

/**
 * Tests the key use enumeration.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-04-03)
 */
//public class KeyUseTest extends TestCase {
main() {


  test('testIdentifiers', () {

    expect("sig", KeyUseParser.getIdentifier(KeyUse.SIGNATURE));
//    expect("sig", KeyUse.SIGNATURE.toString());

    expect("enc", KeyUseParser.getIdentifier(KeyUse.ENCRYPTION));
//    expect("enc", KeyUse.ENCRYPTION.toString());
  });

  test('testParse', () {

    expect(KeyUse.SIGNATURE, KeyUseParser.parse("sig"));
    expect(KeyUse.ENCRYPTION, KeyUseParser.parse("enc"));
  });

  test('testParseException', () {

//		try {
    KeyUseParser.parse("no-such-use");

    fail("");

//		} catch (ParseException e) {
//			// ok
//		}
  });

  test('testParseNull', () {

    expect(KeyUseParser.parse(null), isNull);
  });

/*
*/

}

