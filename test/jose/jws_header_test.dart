library jose_jwt.test.jose.jws_header_test;

import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jose.dart';
import 'package:jose_jwt/src/util.dart';
import 'package:jose_jwt/src/jwk.dart';

/**
 * Tests JWS header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-02-15)
 */
//public class JWSHeaderTest extends TestCase {
main() {

  test('testMinimalConstructor', () {

    JWSHeader h = new JWSHeader.fromAlg(JWSAlgorithm.HS256);

    expect(JWSAlgorithm.HS256, h.getAlgorithm());
    expect(h.getJWKURL(), isNull);
    expect(h.getJWK(), isNull);
    expect(h.getX509CertURL(), isNull);
    expect(h.getX509CertThumbprint(), isNull);
    expect(h.getX509CertSHA256Thumbprint(), isNull);
    expect(h.getX509CertChain(), isNull);
    expect(h.getType(), isNull);
    expect(h.getContentType(), isNull);
    expect(h.getCriticalParams(), isNull);
    expect(h.getCustomParams().isEmpty, isTrue);
  });

  test('testSerializeAndParse', () {

    Set<String> crit = new Set();
    crit.add("iat");
    crit.add("exp");
    crit.add("nbf");

    final Base64URL mod = new Base64URL("abc123");
    final Base64URL exp = new Base64URL("def456");
    final KeyUse use = KeyUse.ENCRYPTION;
    final String kid = "1234";

    RSAKey jwk = new RSAKey.publicKey(mod, exp, use, null, JWEAlgorithm.RSA1_5, kid, null, null, null);

    List<Base64> certChain = new List();
    certChain.add(new Base64("asd"));
    certChain.add(new Base64("fgh"));
    certChain.add(new Base64("jkl"));

    JWSHeader h = new JWSHeaderBuilder(JWSAlgorithm.RS256).
    type(new JOSEObjectType("JWT")).
    contentType("application/json").
    criticalParams(crit).
    jwkURL(Uri.parse("https://example.com/jku.json")).
    jwk(jwk).
    x509CertURL(Uri.parse("https://example/cert.b64")).
    x509CertThumbprint(new Base64URL("789iop")).
    x509CertSHA256Thumbprint(new Base64URL("789asd")).
    x509CertChain(certChain).
    keyID("1234").
    customParam("xCustom", "+++").
    build();


    Base64URL base64URL = h.toBase64URL();

    // Parse back
    h = JWSHeader.parseBase64Url(base64URL);

    expect(JWSAlgorithm.RS256, h.getAlgorithm());
    expect(new JOSEObjectType("JWT"), h.getType());
    expect(h.getCriticalParams().contains("iat"), isTrue);
    expect(h.getCriticalParams().contains("exp"), isTrue);
    expect(h.getCriticalParams().contains("nbf"), isTrue);
    expect(3, h.getCriticalParams().length);
    expect("application/json", h.getContentType());
    expect(Uri.parse("https://example.com/jku.json"), h.getJWKURL());
    expect("1234", h.getKeyID());

    jwk = h.getJWK() as RSAKey;
    expect(jwk, isNotNull);
    expect(new Base64URL("abc123"), jwk.getModulus());
    expect(new Base64URL("def456"), jwk.getPublicExponent());
    expect(KeyUse.ENCRYPTION, jwk.getKeyUse());
    expect(JWEAlgorithm.RSA1_5, jwk.getAlgorithm());
    expect("1234", jwk.getKeyID());

    expect( Uri.parse("https://example/cert.b64"), h.getX509CertURL());
    expect(new Base64URL("789iop"), h.getX509CertThumbprint());
    expect(new Base64URL("789asd"), h.getX509CertSHA256Thumbprint());

    certChain = h.getX509CertChain();
    expect(3, certChain.length);
    expect(new Base64("asd"), certChain[0]);
    expect(new Base64("fgh"), certChain[1]);
    expect(new Base64("jkl"), certChain[2]);

    expect("+++", h.getCustomParam("xCustom") as String);
    expect(1, h.getCustomParams().length);

    expect(base64URL, h.getParsedBase64URL());

    expect(h.getIncludedParams().contains("alg"), isTrue);
    expect(h.getIncludedParams().contains("typ"), isTrue);
    expect(h.getIncludedParams().contains("cty"), isTrue);
    expect(h.getIncludedParams().contains("crit"), isTrue);
    expect(h.getIncludedParams().contains("jku"), isTrue);
    expect(h.getIncludedParams().contains("jwk"), isTrue);
    expect(h.getIncludedParams().contains("kid"), isTrue);
    expect(h.getIncludedParams().contains("x5u"), isTrue);
    expect(h.getIncludedParams().contains("x5t"), isTrue);
    expect(h.getIncludedParams().contains("x5c"), isTrue);
    expect(h.getIncludedParams().contains("xCustom"), isTrue);
    expect(12, h.getIncludedParams().length);

    // Test copy constructor
    h = new JWSHeader.deepCopy(h);

    expect(JWSAlgorithm.RS256, h.getAlgorithm());
    expect(new JOSEObjectType("JWT"), h.getType());
    expect(h.getCriticalParams().contains("iat"), isTrue);
    expect(h.getCriticalParams().contains("exp"), isTrue);
    expect(h.getCriticalParams().contains("nbf"), isTrue);
    expect(3, h.getCriticalParams().length);
    expect("application/json", h.getContentType());
    expect(Uri.parse("https://example.com/jku.json"), h.getJWKURL());
    expect("1234", h.getKeyID());

    jwk = h.getJWK() as RSAKey;
    expect(jwk, isNotNull);
    expect(new Base64URL("abc123"), jwk.getModulus());
    expect(new Base64URL("def456"), jwk.getPublicExponent());
    expect(KeyUse.ENCRYPTION, jwk.getKeyUse());
    expect(JWEAlgorithm.RSA1_5, jwk.getAlgorithm());
    expect("1234", jwk.getKeyID());

    expect(Uri.parse("https://example/cert.b64"), h.getX509CertURL());
    expect(new Base64URL("789iop"), h.getX509CertThumbprint());
    expect(new Base64URL("789asd"), h.getX509CertSHA256Thumbprint());

    certChain = h.getX509CertChain();
    expect(3, certChain.length);
    expect(new Base64("asd"), certChain[0]);
    expect(new Base64("fgh"), certChain[1]);
    expect(new Base64("jkl"), certChain[2]);

    expect("+++", h.getCustomParam("xCustom") as String);
    expect(1, h.getCustomParams().length);

    expect(base64URL, h.getParsedBase64URL());
  });


  test('testParseJSONText', () {

    // Example header from JWS spec

    String s = "{\"typ\":\"JWT\",\"alg\":\"HS256\"}";

    JWSHeader h = JWSHeader.parseJsonString(s);

    expect(h, isNotNull);

    expect(new JOSEObjectType("JWT"), h.getType());
    expect(JWSAlgorithm.HS256, h.getAlgorithm());
    expect(h.getContentType(), isNull);

    expect(h.getIncludedParams().contains("alg"), isTrue);
    expect(h.getIncludedParams().contains("typ"), isTrue);
    expect(2, h.getIncludedParams().length);
  });

  test('testParseBase64URLText', () {

    // Example header from JWS spec

    Base64URL inn = new Base64URL("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");

    JWSHeader h = JWSHeader.parseBase64Url(inn);

    expect(inn, h.toBase64URL());

    expect(new JOSEObjectType("JWT"), h.getType());
    expect(JWSAlgorithm.HS256, h.getAlgorithm());
    expect(h.getContentType(), isNull);
  });


  test('testCrit', () {

    Set<String> crit = new Set();
    crit.add("iat");
    crit.add("exp");
    crit.add("nbf");

    JWSHeader h = new JWSHeaderBuilder(JWSAlgorithm.RS256).
    criticalParams(crit).
    build();

    expect(3, h.getCriticalParams().length);

    Base64URL b64url = h.toBase64URL();

    // Parse back
    h = JWSHeader.parseBase64Url(b64url);

    crit = h.getCriticalParams();

    expect(crit.contains("iat"), isTrue);
    expect(crit.contains("exp"), isTrue);
    expect(crit.contains("nbf"), isTrue);

    expect(3, crit.length);
  });


  test('testRejectNone', () {

//		try {
    new JWSHeader.fromAlg(new JWSAlgorithm.onlyName("none"));

    fail("Failed to raise exception");

//		} catch (IllegalArgumentException e) {
//
//			// ok
//		}
  });


  test('testBuilder', () {

    JWSHeader h = new JWSHeaderBuilder(JWSAlgorithm.HS256).
    type(JOSEObjectType.JOSE).
    contentType("application/json").
    criticalParams(new Set.from(["exp", "nbf"])).
    jwkURL( Uri.parse("http://example.com/jwk.json")).
    jwk(new OctetSequenceKeyBuilder(new Base64URL("xyz")).build()).
    x509CertURL( Uri.parse("http://example.com/cert.pem")).
    x509CertThumbprint(new Base64URL("abc")).
    x509CertSHA256Thumbprint(new Base64URL("abc256")).
    x509CertChain([new Base64("abc"), new Base64("def")]).
    keyID("123").
    customParam("exp", 123).
    customParam("nbf", 456).
    build();

    expect(JWSAlgorithm.HS256, h.getAlgorithm());
    expect(JOSEObjectType.JOSE, h.getType());
    expect("application/json", h.getContentType());
    expect(h.getCriticalParams().contains("exp"), isTrue);
    expect(h.getCriticalParams().contains("nbf"), isTrue);
    expect(2, h.getCriticalParams().length);
    expect("http://example.com/jwk.json", h.getJWKURL().toString());
    expect("xyz", (h.getJWK() as OctetSequenceKey).getKeyValue().toString());
    expect("http://example.com/cert.pem", h.getX509CertURL().toString());
    expect("abc", h.getX509CertThumbprint().toString());
    expect("abc256", h.getX509CertSHA256Thumbprint().toString());
    expect("abc", h.getX509CertChain()[0].toString());
    expect("def", h.getX509CertChain()[1].toString());
    expect(2, h.getX509CertChain().length);
    expect("123", h.getKeyID());
    expect(123, (h.getCustomParam("exp") as int).toInt());
    expect(456, (h.getCustomParam("nbf") as int).toInt());
    expect(2, h.getCustomParams().length);
    expect(h.getParsedBase64URL(), isNull);

    expect(h.getIncludedParams().contains("alg"), isTrue);
    expect(h.getIncludedParams().contains("typ"), isTrue);
    expect(h.getIncludedParams().contains("cty"), isTrue);
    expect(h.getIncludedParams().contains("crit"), isTrue);
    expect(h.getIncludedParams().contains("jku"), isTrue);
    expect(h.getIncludedParams().contains("jwk"), isTrue);
    expect(h.getIncludedParams().contains("x5u"), isTrue);
    expect(h.getIncludedParams().contains("x5t"), isTrue);
    expect(h.getIncludedParams().contains("x5c"), isTrue);
    expect(h.getIncludedParams().contains("kid"), isTrue);
    expect(h.getIncludedParams().contains("exp"), isTrue);
    expect(h.getIncludedParams().contains("nbf"), isTrue);
    expect(13, h.getIncludedParams().length);
  });

  test('testBuilderWithCustomParams', () {

    Map<String, Object> customParams = new Map();
    customParams.put("x", "1");
    customParams.put("y", "2");

    JWSHeader h = new JWSHeaderBuilder(JWSAlgorithm.HS256).
    customParams(customParams).
    build();

    expect("1", h.getCustomParam("x") as String);
    expect("2", h.getCustomParam("y") as String);
    expect(2, h.getCustomParams().length);
  });


  test('testImmutableCustomParams', () {

		Map<String,Object> customParams = new Map();
		customParams.put("x", "1");
		customParams.put("y", "2");

		JWSHeader h = new JWSHeaderBuilder(JWSAlgorithm.HS256).
			customParams(customParams).
			build();

//		try {
			h.getCustomParams().put("x", "3");
			fail();
//		} catch (UnsupportedOperationException e) {
//			// ok
//		}
  });


  test('testImmutableCritHeaders', () {

		JWSHeader h = new JWSHeaderBuilder(JWSAlgorithm.HS256).
			criticalParams(new Set.from(["exp", "nbf"])).
			build();

//		try {
			h.getCriticalParams().remove("exp");
			fail();
//		} catch (UnsupportedOperationException e) {
//			// ok
//		}
  });

}

