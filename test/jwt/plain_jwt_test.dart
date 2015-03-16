library jose_jwt.test.plain_jwt_test;

import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jwt.dart';
import 'package:jose_jwt/src/jose.dart';

/**
 * Tests plain JWT object. Uses test vectors from JWT spec.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-08-21)
 */
//public class PlainJWTTest extends TestCase {

main() {

  test('testClaimsSetConstructor', () {

    JWTClaimsSet claimsSet = new JWTClaimsSet();
    claimsSet.setSubject("alice");
    claimsSet.setIssuer("http://c2id.com");
    claimsSet.setAudience("http://app.example.com");

    ReadOnlyJWTClaimsSet readOnlyClaimsSet = claimsSet;

    PlainJWT jwt = new PlainJWT(readOnlyClaimsSet);

    expect("alice", jwt.getJWTClaimsSet().getSubject());
    expect("http://c2id.com", equals(jwt.getJWTClaimsSet().getIssuer()));
    expect("http://app.example.com", equals(jwt.getJWTClaimsSet().getAudience()[0]));
  });

  test('testHeaderAndClaimsSetConstructor', () {

    PlainHeader header = new PlainHeaderBuilder().customParam("exp", 1000).build();

    JWTClaimsSet claimsSet = new JWTClaimsSet();
    claimsSet.setSubject("alice");
    claimsSet.setIssuer("http://c2id.com");
    claimsSet.setAudience("http://app.example.com");

    ReadOnlyJWTClaimsSet readOnlyClaimsSet = claimsSet;

    PlainJWT jwt = new PlainJWT.fromHeaderAndClaimSet(header, readOnlyClaimsSet);

    expect(header, equals(jwt.getHeader()));

    expect("alice", equals(jwt.getJWTClaimsSet().getSubject()));
    expect("http://c2id.com", equals(jwt.getJWTClaimsSet().getIssuer()));
    expect("http://app.example.com", equals(jwt.getJWTClaimsSet().getAudience()[0]));
  });

  test('testBase64URLConstructor', () {

    // {"alg":"none"}
    Base64URL part1 = new Base64URL("eyJhbGciOiJub25lIn0");

    // {"iss":"joe","exp":1300819380,"http://example.com/is_root":true}
    Base64URL part2 = new Base64URL("eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ");

    PlainJWT jwt = new PlainJWT.fromParts(part1, part2);

    expect(Algorithm.NONE, equals(jwt.getHeader().getAlgorithm()));
    expect(jwt.getHeader().getType(), isNull);
    expect(jwt.getHeader().getContentType(), isNull);

    ReadOnlyJWTClaimsSet cs = jwt.getJWTClaimsSet();

    expect("joe", equals(cs.getIssuer()));
    expect(new DateTime.fromMillisecondsSinceEpoch(1300819380 * 1000), equals(cs.getExpirationTime()));
    expect(cs.getCustomClaim("http://example.com/is_root") as bool, isTrue);
  });

  test('testParse', () {

    String s = "eyJhbGciOiJub25lIn0" +
    "." +
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
    ".";

    PlainJWT jwt = PlainJWT.parse(s);

    expect(Algorithm.NONE, equals(jwt.getHeader().getAlgorithm()));
    expect(jwt.getHeader().getType(), isNull);
    expect(jwt.getHeader().getContentType(), isNull);

    ReadOnlyJWTClaimsSet cs = jwt.getJWTClaimsSet();

    expect("joe", equals(cs.getIssuer()));
    expect(new DateTime.fromMillisecondsSinceEpoch(1300819380 * 1000), equals(cs.getExpirationTime()));
    expect(cs.getCustomClaim("http://example.com/is_root") as bool, isTrue);
  });

  test('testExampleKristina', () {

    String jwtString = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0=\n" +
    ".eyJleHAiOjM3NzQ4NjQwNSwiYXpwIjoiRFAwMWd5M1Frd1ZHR2RJZWpJSmdMWEN0UlRnYSIsInN1\n" +
    "YiI6ImFkbWluQGNhcmJvbi5zdXBlciIsImF1ZCI6IkRQMDFneTNRa3dWR0dkSWVqSUpnTFhDdFJU\n" +
    "Z2EiLCJpc3MiOiJodHRwczpcL1wvbG9jYWxob3N0Ojk0NDNcL29hdXRoMmVuZHBvaW50c1wvdG9r\n" +
    "ZW4iLCJpYXQiOjM3Mzg4NjQwNX0=\n" +
    ".";

    PlainJWT plainJWT = PlainJWT.parse(jwtString);

    // Header
    expect(Algorithm.NONE, equals(plainJWT.getHeader().getAlgorithm()));
    expect(new JOSEObjectType("JWT"), equals(plainJWT.getHeader().getType()));

    // Claims
    expect(new DateTime.fromMillisecondsSinceEpoch(377486405 * 1000), equals(plainJWT.getJWTClaimsSet().getExpirationTime()));
    expect("DP01gy3QkwVGGdIejIJgLXCtRTga", equals(plainJWT.getJWTClaimsSet().getClaim("azp")));
    expect("admin@carbon.super", equals(plainJWT.getJWTClaimsSet().getSubject()));
    expect("DP01gy3QkwVGGdIejIJgLXCtRTga", equals(plainJWT.getJWTClaimsSet().getAudience()[0]));
    expect("https://localhost:9443/oauth2endpoints/token", equals(plainJWT.getJWTClaimsSet().getIssuer()));
    expect(new DateTime.fromMillisecondsSinceEpoch (373886405 * 1000), equals(plainJWT.getJWTClaimsSet().getIssueTime()));
  });

}
