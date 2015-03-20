library jose_jwt.test.jose.plain_header_test;

import 'package:unittest/unittest.dart';

/**
 * Tests plain header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-07-10)
 */
//public class PlainHeaderTest extends TestCase {
main() {

	/*

  test('testMinimalConstructor', () {

		PlainHeader h = new PlainHeader();

		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertNull(h.getType());
		assertNull(h.getContentType());
		assertNull(h.getCriticalParams());
		assertNull(h.getParsedBase64URL());

		Base64URL b64url = h.toBase64URL();

		// Parse back
		h = PlainHeader.parse(b64url);

		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertNull(h.getType());
		assertNull(h.getContentType());
		assertNull(h.getCriticalParams());
		assertEquals(b64url, h.getParsedBase64URL());
		assertEquals(b64url, h.toBase64URL());
  });

  test('testFullAndCopyConstructors', () {

		Set<String> crit = new HashSet<>();
		crit.add("iat");
		crit.add("exp");
		crit.add("nbf");

		Map<String,Object> customParams = new HashMap<>();
		customParams.put("xCustom", "abc");

		PlainHeader h = new PlainHeader(
			new JOSEObjectType("JWT"),
			"application/jwt",
			crit,
			customParams,
			null);

		assertTrue(h.getIncludedParams().contains("alg"));
		assertTrue(h.getIncludedParams().contains("typ"));
		assertTrue(h.getIncludedParams().contains("cty"));
		assertTrue(h.getIncludedParams().contains("crit"));
		assertTrue(h.getIncludedParams().contains("xCustom"));
		assertEquals(5, h.getIncludedParams().size());

		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals("application/jwt", h.getContentType());
		assertEquals(3, h.getCriticalParams().size());
		assertEquals("abc", (String)h.getCustomParam("xCustom"));
		assertEquals(1, h.getCustomParams().size());
		assertNull(h.getParsedBase64URL());

		Base64URL b64url = h.toBase64URL();

		// Parse back
		h = PlainHeader.parse(b64url);

		assertEquals(b64url, h.toBase64URL());

		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals("application/jwt", h.getContentType());
		assertEquals(3, h.getCriticalParams().size());
		assertEquals("abc", (String)h.getCustomParam("xCustom"));
		assertEquals(1, h.getCustomParams().size());
		assertEquals(b64url, h.getParsedBase64URL());

		// Copy
		h = new PlainHeader(h);

		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals("application/jwt", h.getContentType());
		assertEquals(3, h.getCriticalParams().size());
		assertEquals("abc", (String)h.getCustomParam("xCustom"));
		assertEquals(1, h.getCustomParams().size());
		assertEquals(b64url, h.getParsedBase64URL());
  });


  test('testBuilder', () {

		Set<String> crit = new HashSet<>();
		crit.add("iat");
		crit.add("exp");
		crit.add("nbf");

		PlainHeader h = new PlainHeader.Builder().
			type(new JOSEObjectType("JWT")).
			contentType("application/jwt").
			criticalParams(crit).
			customParam("xCustom", "abc").
			build();

		assertTrue(h.getIncludedParams().contains("alg"));
		assertTrue(h.getIncludedParams().contains("typ"));
		assertTrue(h.getIncludedParams().contains("cty"));
		assertTrue(h.getIncludedParams().contains("crit"));
		assertTrue(h.getIncludedParams().contains("xCustom"));
		assertEquals(5, h.getIncludedParams().size());

		Base64URL b64url = h.toBase64URL();

		// Parse back
		h = PlainHeader.parse(b64url);

		assertEquals(b64url, h.toBase64URL());

		assertEquals(Algorithm.NONE, h.getAlgorithm());
		assertEquals(new JOSEObjectType("JWT"), h.getType());
		assertEquals("application/jwt", h.getContentType());
		assertEquals(3, h.getCriticalParams().size());
		assertEquals("abc", (String)h.getCustomParam("xCustom"));
		assertEquals(1, h.getCustomParams().size());
  });


  test('testParseExample', () {

		// Example BASE64URL from JWT spec
		Base64URL in = new Base64URL("eyJhbGciOiJub25lIn0");

		PlainHeader header = PlainHeader.parse(in);

		assertEquals(in, header.toBase64URL());

		assertEquals(Algorithm.NONE, header.getAlgorithm());
  });


  test('testBuilderWithCustomParams', () {

		Map<String,Object> customParams = new HashMap<>();
		customParams.put("x", "1");
		customParams.put("y", "2");

		PlainHeader h = new PlainHeader.Builder().
			customParams(customParams).
			build();

		assertEquals("1", (String)h.getCustomParam("x"));
		assertEquals("2", (String)h.getCustomParam("y"));
		assertEquals(2, h.getCustomParams().size());
  });

*/

}


