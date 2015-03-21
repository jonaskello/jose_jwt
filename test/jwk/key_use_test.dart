library jose_jwt.test.jwk.key_use_test;

/*
/**
 * Tests the key use enumeration.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-04-03)
 */
//public class KeyUseTest extends TestCase {
main() {


  test('testIdentifiers', () {

		assertEquals("sig", KeyUse.SIGNATURE.identifier());
		assertEquals("sig", KeyUse.SIGNATURE.toString());

		assertEquals("enc", KeyUse.ENCRYPTION.identifier());
		assertEquals("enc", KeyUse.ENCRYPTION.toString());
  });

  test('testParse', () {

		assertEquals(KeyUse.SIGNATURE, KeyUse.parse("sig"));
		assertEquals(KeyUse.ENCRYPTION, KeyUse.parse("enc"));
  });

  test('testParseException', () {

		try {
			KeyUse.parse("no-such-use");

			fail();

		} catch (ParseException e) {
			// ok
		}
  });

  test('testParseNull', () {

		assertNull(KeyUse.parse(null));
  });

}

*/
