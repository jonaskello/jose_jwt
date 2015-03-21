library jose_jwt.test.jose.plain_header_test;

import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jose.dart';

/**
 * Tests plain header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-07-10)
 */
//public class PlainHeaderTest extends TestCase {
main() {


  test('testMinimalConstructor', () {

    PlainHeader h = new PlainHeader.minimal();

    expect(Algorithm.NONE, h.getAlgorithm());
    expect(h.getType(), isNull);
    expect(h.getContentType(), isNull);
    expect(h.getCriticalParams(), isNull);
    expect(h.getParsedBase64URL(), isNull);

    Base64URL b64url = h.toBase64URL();

    // Parse back
    h = PlainHeader.parseBase64Url(b64url);

    expect(Algorithm.NONE, h.getAlgorithm());
    expect(h.getType(), isNull);
    expect(h.getContentType(), isNull);
    expect(h.getCriticalParams(), isNull);
    expect(b64url, h.getParsedBase64URL());
    expect(b64url, h.toBase64URL());
  });

  test('testFullAndCopyConstructors', () {

    Set<String> crit = new Set();
    crit.add("iat");
    crit.add("exp");
    crit.add("nbf");

    Map<String, Object> customParams = new Map();
    customParams["xCustom"] = "abc";

    PlainHeader h = new PlainHeader(
        new JOSEObjectType("JWT"),
        "application/jwt",
        crit,
        customParams,
        null);

    expect(h.getIncludedParams().contains("alg"), isTrue);
    expect(h.getIncludedParams().contains("typ"), isTrue);
    expect(h.getIncludedParams().contains("cty"), isTrue);
    expect(h.getIncludedParams().contains("crit"), isTrue);
    expect(h.getIncludedParams().contains("xCustom"), isTrue);
    expect(5, h.getIncludedParams().length);

    expect(Algorithm.NONE, h.getAlgorithm());
    expect(new JOSEObjectType("JWT"), h.getType());
    expect("application/jwt", h.getContentType());
    expect(3, h.getCriticalParams().length);
    expect("abc", h.getCustomParam("xCustom") as String);
    expect(1, h.getCustomParams().length);
    expect(h.getParsedBase64URL(), isNull);

    Base64URL b64url = h.toBase64URL();

    // Parse back
    h = PlainHeader.parseBase64Url(b64url);

    expect(b64url, h.toBase64URL());

    expect(Algorithm.NONE, h.getAlgorithm());
    expect(new JOSEObjectType("JWT"), h.getType());
    expect("application/jwt", h.getContentType());
    expect(3, h.getCriticalParams().length);
    expect("abc", h.getCustomParam("xCustom") as String);
    expect(1, h.getCustomParams().length);
    expect(b64url, h.getParsedBase64URL());

    // Copy
    h = new PlainHeader.deepCopy(h);

    expect(Algorithm.NONE, h.getAlgorithm());
    expect(new JOSEObjectType("JWT"), h.getType());
    expect("application/jwt", h.getContentType());
    expect(3, h.getCriticalParams().length);
    expect("abc", h.getCustomParam("xCustom") as String);
    expect(1, h.getCustomParams().length);
    expect(b64url, h.getParsedBase64URL());
  });


  test('testBuilder', () {

    Set<String> crit = new Set();
    crit.add("iat");
    crit.add("exp");
    crit.add("nbf");

    PlainHeader h = new PlainHeaderBuilder().
    type(new JOSEObjectType("JWT")).
    contentType("application/jwt").
    criticalParams(crit).
    customParam("xCustom", "abc").
    build();

    expect(h.getIncludedParams().contains("alg"), isTrue);
    expect(h.getIncludedParams().contains("typ"), isTrue);
    expect(h.getIncludedParams().contains("cty"), isTrue);
    expect(h.getIncludedParams().contains("crit"), isTrue);
    expect(h.getIncludedParams().contains("xCustom"), isTrue);
    expect(5, h.getIncludedParams().length);

    Base64URL b64url = h.toBase64URL();

    // Parse back
    h = PlainHeader.parseBase64Url(b64url);

    expect(b64url, h.toBase64URL());

    expect(Algorithm.NONE, h.getAlgorithm());
    expect(new JOSEObjectType("JWT"), h.getType());
    expect("application/jwt", h.getContentType());
    expect(3, h.getCriticalParams().length);
    expect("abc", h.getCustomParam("xCustom") as String);
    expect(1, h.getCustomParams().length);
  });


  test('testParseExample', () {

    // Example BASE64URL from JWT spec
    Base64URL inn = new Base64URL("eyJhbGciOiJub25lIn0");

    PlainHeader header = PlainHeader.parseBase64Url(inn);

    expect(inn, header.toBase64URL());

    expect(Algorithm.NONE, header.getAlgorithm());
  });


  test('testBuilderWithCustomParams', () {

    Map<String, Object> customParams = new Map();
    customParams["x"] = "1";
    customParams["y"] = "2";

    PlainHeader h = new PlainHeaderBuilder().
    customParams(customParams).
    build();

    expect("1", h.getCustomParam("x") as String);
    expect("2", h.getCustomParam("y") as String);
    expect(2, h.getCustomParams().length);
  });


}


