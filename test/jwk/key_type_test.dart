library jose_jwt.test.jwk.key_type_test;

/*
/**
 * Tests the key type class.
 */
//public class KeyTypeTest extends TestCase {
main() {


  test('testConstants', () {

		assertEquals("RSA", KeyType.RSA.getValue());
		assertEquals(Requirement.REQUIRED, KeyType.RSA.getRequirement());

		assertEquals("EC", KeyType.EC.getValue());
		assertEquals(Requirement.RECOMMENDED, KeyType.EC.getRequirement());

		assertEquals("oct", KeyType.OCT.getValue());
		assertEquals(Requirement.OPTIONAL, KeyType.OCT.getRequirement());
  });

}

*/
