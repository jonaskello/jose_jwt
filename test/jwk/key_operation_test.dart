library jose_jwt.test.jwk.key_operation_test;

/*
/**
 * Tests the key operation enumeration.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-04-03)
 */
//public class KeyOperationTest extends TestCase {
main() {


  test('testIdentifiers', () {

		assertEquals("sign", KeyOperation.SIGN.identifier());
		assertEquals("sign", KeyOperation.SIGN.toString());

		assertEquals("verify", KeyOperation.VERIFY.identifier());
		assertEquals("verify", KeyOperation.VERIFY.toString());

		assertEquals("encrypt", KeyOperation.ENCRYPT.identifier());
		assertEquals("encrypt", KeyOperation.ENCRYPT.toString());

		assertEquals("decrypt", KeyOperation.DECRYPT.identifier());
		assertEquals("decrypt", KeyOperation.DECRYPT.toString());

		assertEquals("wrapKey", KeyOperation.WRAP_KEY.identifier());
		assertEquals("wrapKey", KeyOperation.WRAP_KEY.toString());

		assertEquals("unwrapKey", KeyOperation.UNWRAP_KEY.identifier());
		assertEquals("unwrapKey", KeyOperation.UNWRAP_KEY.toString());

		assertEquals("deriveKey", KeyOperation.DERIVE_KEY.identifier());
		assertEquals("deriveKey", KeyOperation.DERIVE_KEY.toString());

		assertEquals("deriveBits", KeyOperation.DERIVE_BITS.identifier());
		assertEquals("deriveBits", KeyOperation.DERIVE_BITS.toString());
  });

  test('testParseNull', () {

		assertNull(KeyOperation.parse(null));
  });

  test('testParseSparseList', () {

		List<String> sl = Arrays.asList("sign", null, "verify");

		Set<KeyOperation> ops = KeyOperation.parse(sl);
		assertTrue(ops.contains(KeyOperation.SIGN));
		assertTrue(ops.contains(KeyOperation.VERIFY));
		assertEquals(2, ops.size());
  });

  test('testParseList', () {

		List<String> sl = Arrays.asList("sign", "verify");

		Set<KeyOperation> ops = KeyOperation.parse(sl);
		assertTrue(ops.contains(KeyOperation.SIGN));
		assertTrue(ops.contains(KeyOperation.VERIFY));
		assertEquals(2, ops.size());
  });

  test('testParseException', () {

		List<String> sl = Arrays.asList("sign", "no-such-op", "verify");

		try {
			KeyOperation.parse(sl);
			fail();
		} catch (ParseException e) {
			// ok
		}
  });

}

*/
