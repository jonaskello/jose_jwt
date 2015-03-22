library jose_jwt.test.jwk.key_operation_test;

import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jwk.dart';
import 'package:jose_jwt/src/errors.dart';

/**
 * Tests the key operation enumeration.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-04-03)
 */
//public class KeyOperationTest extends TestCase {
main() {

	expectTrue(a) {
		return expect(a, isTrue);
	}

  test('testIdentifiers', () {

//		expect("sign", KeyOperation.SIGN.identifier());
		expect("sign", KeyOperation.SIGN.toString());

//		expect("verify", KeyOperation.VERIFY.identifier());
		expect("verify", KeyOperation.VERIFY.toString());

//		expect("encrypt", KeyOperation.ENCRYPT.identifier());
		expect("encrypt", KeyOperation.ENCRYPT.toString());

//		expect("decrypt", KeyOperation.DECRYPT.identifier());
		expect("decrypt", KeyOperation.DECRYPT.toString());

//		expect("wrapKey", KeyOperation.WRAP_KEY.identifier());
		expect("wrapKey", KeyOperation.WRAP_KEY.toString());

//		expect("unwrapKey", KeyOperation.UNWRAP_KEY.identifier());
		expect("unwrapKey", KeyOperation.UNWRAP_KEY.toString());

//		expect("deriveKey", KeyOperation.DERIVE_KEY.identifier());
		expect("deriveKey", KeyOperation.DERIVE_KEY.toString());

//		expect("deriveBits", KeyOperation.DERIVE_BITS.identifier());
		expect("deriveBits", KeyOperation.DERIVE_BITS.toString());
  });

  test('testParseNull', () {

		expect(KeyOperationParser.parse(null), isNull);
  });

  test('testParseSparseList', () {

		List<String> sl = ["sign", null, "verify"];

		Set<KeyOperation> ops = KeyOperationParser.parse(sl);
		expectTrue(ops.contains(KeyOperation.SIGN));
		expectTrue(ops.contains(KeyOperation.VERIFY));
		expect(2, ops.length);
  });

  test('testParseList', () {

		List<String> sl = ["sign", "verify"];

		Set<KeyOperation> ops = KeyOperationParser.parse(sl);
		expectTrue(ops.contains(KeyOperation.SIGN));
		expectTrue(ops.contains(KeyOperation.VERIFY));
		expect(2, ops.length);
  });


  test('testParseException', () {

		List<String> sl = ["sign", "no-such-op", "verify"];

//		try {
		expect(()=>
		KeyOperationParser.parse(sl),
		throwsA(new isInstanceOf<ParseError>()));
//			fail("");
//		} catch (ParseException e) {
//			// ok
//		}
  });

/*
*/

}

