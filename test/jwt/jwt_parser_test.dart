library jose_jwt.test.jwt_parser_test;

import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jwt.dart';
import 'package:jose_jwt/src/jose.dart';

/**
 * Tests the JWT parser. Uses test vectors from JWT spec.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-08-21)
 */
//public class JWTParserTest extends TestCase {

main() {

  test('testParsePlainJWT', () {

    String s = "eyJhbGciOiJub25lIn0" +
    "." +
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt" +
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ" +
    ".";

    JWT jwt = JWTParser.parse(s);

    expect(Algorithm.NONE, equals(jwt.getHeader().getAlgorithm()));

    expect(jwt is PlainJWT, isTrue);

    PlainJWT plainJWT = jwt as PlainJWT;

    expect(Algorithm.NONE, equals(plainJWT.getHeader().getAlgorithm()));
    expect(plainJWT.getHeader().getType(), isNull);
    expect(plainJWT.getHeader().getContentType(), isNull);

    ReadOnlyJWTClaimsSet cs = plainJWT.getJWTClaimsSet();

    expect("joe", equals(cs.getIssuer()));
    expect(new DateTime.fromMillisecondsSinceEpoch(1300819380 * 1000), equals(cs.getExpirationTime()));
    expect(cs.getCustomClaim("http://example.com/is_root") as bool, isTrue);

  });

  test('testParseEncryptedJWT', () {

    String s = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0." +
    "QR1Owv2ug2WyPBnbQrRARTeEk9kDO2w8qDcjiHnSJflSdv1iNqhWXaKH4MqAkQtM" +
    "oNfABIPJaZm0HaA415sv3aeuBWnD8J-Ui7Ah6cWafs3ZwwFKDFUUsWHSK-IPKxLG" +
    "TkND09XyjORj_CHAgOPJ-Sd8ONQRnJvWn_hXV1BNMHzUjPyYwEsRhDhzjAD26ima" +
    "sOTsgruobpYGoQcXUwFDn7moXPRfDE8-NoQX7N7ZYMmpUDkR-Cx9obNGwJQ3nM52" +
    "YCitxoQVPzjbl7WBuB7AohdBoZOdZ24WlN1lVIeh8v1K4krB8xgKvRU8kgFrEn_a" +
    "1rZgN5TiysnmzTROF869lQ." +
    "AxY8DCtDaGlsbGljb3RoZQ." +
    "MKOle7UQrG6nSxTLX6Mqwt0orbHvAKeWnDYvpIAeZ72deHxz3roJDXQyhxx0wKaM" +
    "HDjUEOKIwrtkHthpqEanSBNYHZgmNOV7sln1Eu9g3J8." +
    "fiK51VwhsxJ-siBMR-YFiA";

    JWT jwt = JWTParser.parse(s);

    expect(JWEAlgorithm.RSA1_5, equals(jwt.getHeader().getAlgorithm()));

    expect(jwt is EncryptedJWT, isTrue);

    EncryptedJWT encryptedJWT = jwt as EncryptedJWT;

    expect(JWEObjectState.ENCRYPTED, equals(encryptedJWT.getState()));

    expect(JWEAlgorithm.RSA1_5, equals(encryptedJWT.getHeader().getAlgorithm()));
    expect(EncryptionMethod.A128CBC_HS256, equals(encryptedJWT.getHeader().getEncryptionMethod()));
    expect(encryptedJWT.getHeader().getType(), isNull);
    expect(encryptedJWT.getHeader().getContentType(), isNull);
  });

}
