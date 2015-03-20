library jose_jwt.test.jose.header_test;

import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jose.dart';

/**
 * Tests the base JOSE header class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-08-20)
 */
//public class HeaderTest extends TestCase {

main() {

  test('testParsePlainHeaderFromBase64URL', () {

    // Example BASE64URL from JWT spec
    Base64URL inn = new Base64URL("eyJhbGciOiJub25lIn0");

    Header header = Header.parseBase64Url(inn);

    expect(header is PlainHeader, isTrue);
    expect(inn, header.toBase64URL());
    expect(Algorithm.NONE, header.getAlgorithm());
  });

  test('testParseJWSHeaderFromBase64URL', () {

    // Example BASE64URL from JWS spec
    Base64URL inn = new Base64URL("eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");

    Header header = Header.parseBase64Url(inn);

    expect(header is JWSHeader, isTrue);
    expect(inn, header.toBase64URL());
    expect(JWSAlgorithm.HS256, header.getAlgorithm());
  });

  test('testParseJWEHeaderFromBase64URL', () {

    // Example BASE64URL from JWE spec
    Base64URL inn = new Base64URL("eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0");

    Header header = Header.parseBase64Url(inn);

    expect(header is JWEHeader, isTrue);
    expect(inn, header.toBase64URL());
    expect(JWEAlgorithm.RSA1_5, header.getAlgorithm());

    JWEHeader jweHeader = header as JWEHeader;
    expect(EncryptionMethod.A128CBC_HS256, jweHeader.getEncryptionMethod());
  });

}
