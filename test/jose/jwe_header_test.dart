library jose_jwt.test.jose.jwe_header_test;

import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jose.dart';
import 'package:jose_jwt/src/util.dart';
import 'package:jose_jwt/src/jwk.dart';

/**
 * Tests JWE header parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-02-15)
 */
//public class JWEHeaderTest extends TestCase {
main() {

  test('testMinimalConstructor', () {

    JWEHeader h = new JWEHeader.minimal(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM);

    expect(JWEAlgorithm.A128KW, h.getAlgorithm());
    expect(EncryptionMethod.A128GCM, h.getEncryptionMethod());
    expect(h.getJWKURL(), isNull);
    expect(h.getJWK(), isNull);
    expect(h.getX509CertURL(), isNull);
    expect(h.getX509CertThumbprint(), isNull);
    expect(h.getX509CertSHA256Thumbprint(), isNull);
    expect(h.getX509CertChain(), isNull);
    expect(h.getType(), isNull);
    expect(h.getContentType(), isNull);
    expect(h.getCriticalParams(), isNull);
    expect(h.getEphemeralPublicKey(), isNull);
    expect(h.getCompressionAlgorithm(), isNull);
    expect(h.getAgreementPartyUInfo(), isNull);
    expect(h.getAgreementPartyVInfo(), isNull);
    expect(h.getPBES2Salt(), isNull);
    expect(h.getIV(), isNull);
    expect(h.getAuthTag(), isNull);
    expect(0, h.getPBES2Count());
    expect(h.getCustomParams().isEmpty, isTrue);
  });


  test('testParse1', () {

    // Example header from JWE spec
    // {"alg":"RSA-OAEP","enc":"A256GCM"}
    Base64URL inn = new Base64URL("eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ");

    JWEHeader h = JWEHeader.parseBase64Url(inn);

    expect(inn, h.toBase64URL());

    expect(h, isNotNull);

    expect(JWEAlgorithm.RSA_OAEP, h.getAlgorithm());
    expect(EncryptionMethod.A256GCM, h.getEncryptionMethod());

    expect(h.getType(), isNull);
    expect(h.getContentType(), isNull);

    expect(h.getIncludedParams().contains("alg"), isTrue);
    expect(h.getIncludedParams().contains("enc"), isTrue);
    expect(2, h.getIncludedParams().length);
  });

  test('testParse2', () {

    // Example header from JWE spec
    // {"alg":"RSA1_5","enc":"A128CBC-HS256"}
    Base64URL inn = new Base64URL("eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0");

    JWEHeader h = JWEHeader.parseBase64Url(inn);

    expect(inn, h.toBase64URL());

    expect(h, isNotNull);

    expect(JWEAlgorithm.RSA1_5, h.getAlgorithm());
    expect(EncryptionMethod.A128CBC_HS256, h.getEncryptionMethod());

    expect(h.getType(), isNull);
    expect(h.getContentType(), isNull);

    expect(h.getIncludedParams().contains("alg"), isTrue);
    expect(h.getIncludedParams().contains("enc"), isTrue);
    expect(2, h.getIncludedParams().length);
  });


  test('testSerializeAndParse', () {

    final Base64URL mod = new Base64URL("abc123");
    final Base64URL exp = new Base64URL("def456");
    final KeyUse use = KeyUse.ENCRYPTION;
    final String kid = "1234";

    RSAKey jwk = new RSAKey.publicKey(mod, exp, use, null, JWEAlgorithm.RSA1_5, kid, null, null, null);

    List<Base64> certChain = new List();
    certChain.add(new Base64("asd"));
    certChain.add(new Base64("fgh"));
    certChain.add(new Base64("jkl"));

    JWEHeader h = new JWEHeaderBuilder(JWEAlgorithm.RSA1_5, EncryptionMethod.A256GCM).
    type(new JOSEObjectType("JWT")).
    compressionAlgorithm(CompressionAlgorithm.DEF).
    jwkURL(Uri.parse("https://example.com/jku.json")).
    jwk(jwk).
    x509CertURL(Uri.parse("https://example/cert.b64")).
    x509CertThumbprint(new Base64URL("789iop")).
    x509CertSHA256Thumbprint(new Base64URL("789asd")).
    x509CertChain(certChain).
    keyID("1234").
    agreementPartyUInfo(new Base64URL("abc")).
    agreementPartyVInfo(new Base64URL("xyz")).
    pbes2Salt(new Base64URL("omg")).
    pbes2Count(1000).
    iv(new Base64URL("101010")).
    authTag(new Base64URL("202020")).
    customParam("xCustom", "+++").
    build();


    Base64URL base64URL = h.toBase64URL();

    // Parse back
    h = JWEHeader.parseBase64Url(base64URL);

    expect(JWEAlgorithm.RSA1_5, h.getAlgorithm());
    expect(new JOSEObjectType("JWT"), h.getType());
    expect(EncryptionMethod.A256GCM, h.getEncryptionMethod());
    expect(CompressionAlgorithm.DEF, h.getCompressionAlgorithm());
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

    expect(new Base64URL("abc"), h.getAgreementPartyUInfo());
    expect(new Base64URL("xyz"), h.getAgreementPartyVInfo());

    expect(new Base64URL("omg"), h.getPBES2Salt());
    expect(1000, h.getPBES2Count());

    expect(new Base64URL("101010"), h.getIV());
    expect(new Base64URL("202020"), h.getAuthTag());

    expect("+++", h.getCustomParam("xCustom") as String);
    expect(1, h.getCustomParams().length);

    expect(base64URL, h.getParsedBase64URL());

    expect(h.getIncludedParams().contains("alg"), isTrue);
    expect(h.getIncludedParams().contains("typ"), isTrue);
    expect(h.getIncludedParams().contains("enc"), isTrue);
    expect(h.getIncludedParams().contains("zip"), isTrue);
    expect(h.getIncludedParams().contains("jku"), isTrue);
    expect(h.getIncludedParams().contains("jwk"), isTrue);
    expect(h.getIncludedParams().contains("kid"), isTrue);
    expect(h.getIncludedParams().contains("x5u"), isTrue);
    expect(h.getIncludedParams().contains("x5t"), isTrue);
    expect(h.getIncludedParams().contains("x5c"), isTrue);
    expect(h.getIncludedParams().contains("apu"), isTrue);
    expect(h.getIncludedParams().contains("apv"), isTrue);
    expect(h.getIncludedParams().contains("p2s"), isTrue);
    expect(h.getIncludedParams().contains("p2c"), isTrue);
    expect(h.getIncludedParams().contains("iv"), isTrue);
    expect(h.getIncludedParams().contains("tag"), isTrue);
    expect(h.getIncludedParams().contains("xCustom"), isTrue);
    expect(18, h.getIncludedParams().length);

    // Test copy constructor
    h = new JWEHeader.deepCopy(h);

    expect(JWEAlgorithm.RSA1_5, h.getAlgorithm());
    expect(new JOSEObjectType("JWT"), h.getType());
    expect(EncryptionMethod.A256GCM, h.getEncryptionMethod());
    expect(CompressionAlgorithm.DEF, h.getCompressionAlgorithm());
    expect( Uri.parse("https://example.com/jku.json"), h.getJWKURL());
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

    expect(new Base64URL("abc"), h.getAgreementPartyUInfo());
    expect(new Base64URL("xyz"), h.getAgreementPartyVInfo());

    expect(new Base64URL("omg"), h.getPBES2Salt());
    expect(1000, h.getPBES2Count());

    expect(new Base64URL("101010"), h.getIV());
    expect(new Base64URL("202020"), h.getAuthTag());

    expect("+++", h.getCustomParam("xCustom") as String);
    expect(1, h.getCustomParams().length);

    expect(base64URL, h.getParsedBase64URL());
  });

  test('testCrit', () {

    Set<String> crit = new Set();
    crit.add("iat");
    crit.add("exp");
    crit.add("nbf");

    JWEHeader h = new JWEHeaderBuilder(JWEAlgorithm.RSA1_5, EncryptionMethod.A128CBC_HS256).
    criticalParams(crit).
    build();

    expect(3, h.getCriticalParams().length);

    Base64URL b64url = h.toBase64URL();

    // Parse back
    h = JWEHeader.parseBase64Url(b64url);

    crit = h.getCriticalParams();

    expect(crit.contains("iat"), isTrue);
    expect(crit.contains("exp"), isTrue);
    expect(crit.contains("nbf"), isTrue);

    expect(3, crit.length);
  });

  test('testRejectNone', () {

//		try {
    new JWEHeader.minimal(new JWEAlgorithm.onlyName("none"), EncryptionMethod.A128CBC_HS256);

    fail("Failed to raise exception");

//		} catch (IllegalArgumentException e) {
//
//			// ok
//		}
  });

  test('testBuilder', () {

    JWEHeader h = new JWEHeaderBuilder(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM).
    type(JOSEObjectType.JOSE).
    contentType("application/json").
    criticalParams(new Set.from(["exp", "nbf"])).
    jwkURL(Uri.parse("http://example.com/jwk.json")).
    jwk(new OctetSequenceKeyBuilder(new Base64URL("xyz")).build()).
    x509CertURL(Uri.parse("http://example.com/cert.pem")).
    x509CertThumbprint(new Base64URL("abc")).
    x509CertSHA256Thumbprint(new Base64URL("abc256")).
    x509CertChain([new Base64("abc"), new Base64("def")]).
    keyID("123").
    compressionAlgorithm(CompressionAlgorithm.DEF).
    agreementPartyUInfo(new Base64URL("qwe")).
    agreementPartyVInfo(new Base64URL("rty")).
    pbes2Salt(new Base64URL("uiop")).
    pbes2Count(1000).
    iv(new Base64URL("101010")).
    authTag(new Base64URL("202020")).
    customParam("exp", 123).
    customParam("nbf", 456).
    build();

    expect(JWEAlgorithm.A128KW, h.getAlgorithm());
    expect(EncryptionMethod.A128GCM, h.getEncryptionMethod());
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
    expect(CompressionAlgorithm.DEF, h.getCompressionAlgorithm());
    expect("qwe", h.getAgreementPartyUInfo().toString());
    expect("rty", h.getAgreementPartyVInfo().toString());
    expect("uiop", h.getPBES2Salt().toString());
    expect(1000, h.getPBES2Count());
    expect("101010", h.getIV().toString());
    expect("202020", h.getAuthTag().toString());
    expect(123, (h.getCustomParam("exp") as int).toInt());
    expect(456, (h.getCustomParam("nbf") as int).toInt());
    expect(2, h.getCustomParams().length);
    expect(h.getParsedBase64URL(), isNull);

    expect(h.getIncludedParams().contains("alg"), isTrue);
    expect(h.getIncludedParams().contains("enc"), isTrue);
    expect(h.getIncludedParams().contains("typ"), isTrue);
    expect(h.getIncludedParams().contains("cty"), isTrue);
    expect(h.getIncludedParams().contains("crit"), isTrue);
    expect(h.getIncludedParams().contains("jku"), isTrue);
    expect(h.getIncludedParams().contains("jwk"), isTrue);
    expect(h.getIncludedParams().contains("x5u"), isTrue);
    expect(h.getIncludedParams().contains("x5t"), isTrue);
    expect(h.getIncludedParams().contains("x5t#S256"), isTrue);
    expect(h.getIncludedParams().contains("x5c"), isTrue);
    expect(h.getIncludedParams().contains("kid"), isTrue);
    expect(h.getIncludedParams().contains("zip"), isTrue);
    expect(h.getIncludedParams().contains("apu"), isTrue);
    expect(h.getIncludedParams().contains("apv"), isTrue);
    expect(h.getIncludedParams().contains("p2s"), isTrue);
    expect(h.getIncludedParams().contains("p2c"), isTrue);
    expect(h.getIncludedParams().contains("iv"), isTrue);
    expect(h.getIncludedParams().contains("tag"), isTrue);
    expect(h.getIncludedParams().contains("exp"), isTrue);
    expect(h.getIncludedParams().contains("nbf"), isTrue);
    expect(21, h.getIncludedParams().length);
  });

  test('testBuilderWithCustomParams', () {

    Map<String, Object> customParams = new Map();
    customParams["x"] = "1";
    customParams["y"] = "2";

    JWEHeader h = new JWEHeaderBuilder(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM).
    customParams(customParams).
    build();

    expect("1", h.getCustomParam("x") as String);
    expect("2", h.getCustomParam("y") as String);
    expect(2, h.getCustomParams().length);
  });

}
