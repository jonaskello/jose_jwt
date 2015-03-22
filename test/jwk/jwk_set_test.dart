library jose_jwt.test.jwk.jwk_set_test;

import 'dart:convert';
import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jwk.dart';
import 'package:jose_jwt/src/jose.dart';
import 'package:jose_jwt/src/util.dart';

/**
 * Tests JSON Web Key (JWK) set parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-12-14)
 */
//public class JWKSetTest extends TestCase {
main() {

  expectNull(a) {
    return expect(a, isNull);
  }

  expectFalse(a) {
    return expect(a, isFalse);
  }

  expectTrue(a) {
    return expect(a, isTrue);
  }


  test('testParsePublicJWKSet', () {

    // The string is from the JWK spec
    String s = "{\"keys\":" +
    "[" +
    "{\"kty\":\"EC\"," +
    "\"crv\":\"P-256\"," +
    "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"," +
    "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"," +
    "\"use\":\"enc\"," +
    "\"kid\":\"1\"}," +
    " " +
    "{\"kty\":\"RSA\"," +
    "\"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
    "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
    "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
    "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
    "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
    "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"," +
    "\"e\":\"AQAB\"," +
    "\"alg\":\"RS256\"," +
    "\"kid\":\"2011-04-29\"}" +
    "]" +
    "}";


    JWKSet keySet = JWKSet.parseJsonString(s);


    List<JWK> keyList = keySet.getKeys();
    expect(2, keyList.length);


    // Check first EC key
    JWK key = keyList[0];

    expectTrue(key is ECKey);
    expect("1", key.getKeyID());
    expect(KeyUse.ENCRYPTION, key.getKeyUse());

    ECKey ecKey = key as ECKey;
    expect(ECKeyCurve.P_256, ecKey.getCurve());
    expect("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", ecKey.getX().toString());
    expect("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", ecKey.getY().toString());
    expectFalse(key.isPrivate());


    // Check second RSA key
    key = keyList[1];
    expectTrue(key is RSAKey);
    expect("2011-04-29", key.getKeyID());
    expectNull(key.getKeyUse());
    expect(JWSAlgorithm.RS256, key.getAlgorithm());

    RSAKey rsaKey = key as RSAKey;
    expect("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
    "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
    "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
    "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
    "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
    "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    rsaKey.getModulus().toString());
    expect("AQAB", rsaKey.getPublicExponent().toString());
    expectFalse(key.isPrivate());
  });


  test('testSerializeAndParsePublicJWKSet', () {

    ECKey ecKey = new ECKey.key(ECKeyCurve.P_256,
    new Base64URL("abc"),
    new Base64URL("def"),
    KeyUse.ENCRYPTION,
    null,
    JWEAlgorithm.ECDH_ES,
    "1234",
    null, null, null);

    RSAKey rsaKey = new RSAKey.publicKey(new Base64URL("abc"),
    new Base64URL("def"),
    KeyUse.SIGNATURE,
    null,
    JWSAlgorithm.RS256,
    "5678",
    null, null, null);

    JWKSet keySet = new JWKSet();

    keySet.getKeys().add(ecKey);
    keySet.getKeys().add(rsaKey);

    expect(0, keySet.getAdditionalMembers().length);

    keySet.getAdditionalMembers()["setID"] = "xyz123";

    expect(1, keySet.getAdditionalMembers().length);

    String s = JSON.encode(keySet.toJson());

    keySet = JWKSet.parseJsonString(s);

    expect(keySet, isNotNull);
    expect(2, keySet.getKeys().length);

    // Check first EC key
    ecKey = keySet.getKeys()[0] as ECKey;
    expect(ecKey, isNotNull);
    expect(ECKeyCurve.P_256, ecKey.getCurve());
    expect("abc", ecKey.getX().toString());
    expect("def", ecKey.getY().toString());
    expect(KeyUse.ENCRYPTION, ecKey.getKeyUse());
    expectNull(ecKey.getKeyOperations());
    expect(JWEAlgorithm.ECDH_ES, ecKey.getAlgorithm());
    expect("1234", ecKey.getKeyID());

    // Check second RSA key
    rsaKey = keySet.getKeys()[1] as RSAKey;
    expect(rsaKey, isNotNull);
    expect("abc", rsaKey.getModulus().toString());
    expect("def", rsaKey.getPublicExponent().toString());
    expect(KeyUse.SIGNATURE, rsaKey.getKeyUse());
    expectNull(rsaKey.getKeyOperations());
    expect(JWSAlgorithm.RS256, rsaKey.getAlgorithm());
    expect("5678", rsaKey.getKeyID());

    // Check additional JWKSet members
    expect(1, keySet.getAdditionalMembers().length);
    expect("xyz123", keySet.getAdditionalMembers()["setID"] as String);

  });

  test('testParseOctetSequenceJWKSet', () {

    // The string is from the JPSK spec
    String s = "{\"keys\":" +
    "[" +
    " {\"kty\":\"oct\"," +
    "  \"alg\":\"A128KW\", " +
    "  \"k\":\"GawgguFyGrWKav7AX4VKUg\"}," +
    " {\"kty\":\"oct\", " +
    "  \"k\":\"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow\"," +
    "  \"kid\":\"HMAC key used in JWS A.1 example\"} " +
    "]" +
    "}";


    JWKSet keySet = JWKSet.parseJsonString(s);

    List<JWK> keyList = keySet.getKeys();
    expect(2, keyList.length);

    // First OCT key
    JWK key = keyList[0];
    expectTrue(key is OctetSequenceKey);
    expect(KeyType.OCT, key.getKeyType());
    expectNull(key.getKeyUse());
    expect(JWEAlgorithm.A128KW, key.getAlgorithm());
    expectNull(key.getKeyID());
    expect(new Base64URL("GawgguFyGrWKav7AX4VKUg"), (key as OctetSequenceKey).getKeyValue());

    // Second OCT key
    key = keyList[1];
    expectTrue(key is OctetSequenceKey);
    expect(KeyType.OCT, key.getKeyType());
    expectNull(key.getKeyUse());
    expectNull(key.getKeyOperations());
    expectNull(key.getAlgorithm());
    expect("HMAC key used in JWS A.1 example", key.getKeyID());
    expect(new Base64URL("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"), (key as OctetSequenceKey).getKeyValue());
  });

  test('testParsePrivateJWKSet', () {

    // The string is from the JPSK spec
    String s = "{\"keys\":" +
    "  [" +
    "    {\"kty\":\"EC\"," +
    "     \"crv\":\"P-256\"," +
    "     \"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"," +
    "     \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"," +
    "     \"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\"," +
    "     \"use\":\"enc\"," +
    "     \"kid\":\"1\"}," +
    "" +
    "    {\"kty\":\"RSA\"," +
    "     \"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4" +
    "cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst" +
    "n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q" +
    "vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS" +
    "D08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw" +
    "0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"," +
    "     \"e\":\"AQAB\"," +
    "     \"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9" +
    "M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij" +
    "wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d" +
    "_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz" +
    "nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz" +
    "me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q\"," +
    "     \"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV" +
    "nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV" +
    "WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\"," +
    "     \"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum" +
    "qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx" +
    "kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk\"," +
    "     \"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim" +
    "YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu" +
    "YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\"," +
    "     \"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU" +
    "vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9" +
    "GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk\"," +
    "     \"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg" +
    "UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx" +
    "yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\"," +
    "     \"alg\":\"RS256\"," +
    "     \"kid\":\"2011-04-29\"}" +
    "  ]" +
    "}";

    JWKSet keySet = null;

    try {
      keySet = JWKSet.parseJsonString(s);

    } catch (e) {
      if (e is ParseError)
        fail(e.toString());
      throw e;
    }

    List<JWK> keyList = keySet.getKeys();
    expect(2, keyList.length);


    // Check EC key
    JWK key = keyList[0];
    expectTrue(key is ECKey);
    expect(KeyUse.ENCRYPTION, key.getKeyUse());
    expectNull(key.getAlgorithm());
    expect("1", key.getKeyID());

    ECKey ecKey = key as ECKey;

    expect(ECKeyCurve.P_256, ecKey.getCurve());
    expect("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", ecKey.getX().toString());
    expect("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", ecKey.getY().toString());
    expect("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE", ecKey.getD().toString());

    expectNull(ecKey.toPublicJWK().getD());


    // Check RSA key
    key = keyList[1];
    expectTrue(key is RSAKey);
    expectNull(key.getKeyUse());
    expectNull(key.getKeyOperations());
    expect(JWSAlgorithm.RS256, key.getAlgorithm());
    expect("2011-04-29", key.getKeyID());

    RSAKey rsaKey = key as RSAKey;

    expect("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
    "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
    "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
    "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
    "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
    "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    rsaKey.getModulus().toString());

    expect("AQAB", rsaKey.getPublicExponent().toString());


    expect("X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9" +
    "M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij" +
    "wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d" +
    "_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz" +
    "nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz" +
    "me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
    rsaKey.getPrivateExponent().toString());

    expect("83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV" +
    "nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV" +
    "WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
    rsaKey.getFirstPrimeFactor().toString());

    expect("3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum" +
    "qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx" +
    "kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
    rsaKey.getSecondPrimeFactor().toString());

    expect("G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim" +
    "YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu" +
    "YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
    rsaKey.getFirstFactorCRTExponent().toString());

    expect("s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU" +
    "vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9" +
    "GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
    rsaKey.getSecondFactorCRTExponent().toString());

    expect("GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg" +
    "UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx" +
    "yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
    rsaKey.getFirstCRTCoefficient().toString());

    expectTrue(rsaKey.getOtherPrimes().isEmpty);

    expectNull(rsaKey.toPublicJWK().getPrivateExponent());
    expectNull(rsaKey.toPublicJWK().getFirstPrimeFactor());
    expectNull(rsaKey.toPublicJWK().getSecondPrimeFactor());
    expectNull(rsaKey.toPublicJWK().getFirstFactorCRTExponent());
    expectNull(rsaKey.toPublicJWK().getSecondFactorCRTExponent());
    expectNull(rsaKey.toPublicJWK().getFirstCRTCoefficient());
    expectTrue(rsaKey.toPublicJWK().getOtherPrimes().isEmpty);
  });

  test('testPublicJSONObjectSerialization', () {

    // The string is from the JPSK spec
    String s = "{\"keys\":" +
    "  [" +
    "    {\"kty\":\"EC\"," +
    "     \"crv\":\"P-256\"," +
    "     \"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"," +
    "     \"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"," +
    "     \"d\":\"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE\"," +
    "     \"use\":\"enc\"," +
    "     \"kid\":\"1\"}," +
    "" +
    "    {\"kty\":\"RSA\"," +
    "     \"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4" +
    "cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst" +
    "n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q" +
    "vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS" +
    "D08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw" +
    "0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"," +
    "     \"e\":\"AQAB\"," +
    "     \"d\":\"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9" +
    "M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij" +
    "wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d" +
    "_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz" +
    "nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz" +
    "me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q\"," +
    "     \"p\":\"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV" +
    "nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV" +
    "WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs\"," +
    "     \"q\":\"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum" +
    "qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx" +
    "kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk\"," +
    "     \"dp\":\"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim" +
    "YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu" +
    "YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0\"," +
    "     \"dq\":\"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU" +
    "vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9" +
    "GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk\"," +
    "     \"qi\":\"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg" +
    "UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx" +
    "yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU\"," +
    "     \"alg\":\"RS256\"," +
    "     \"kid\":\"2011-04-29\"}" +
    "  ]" +
    "}";


    JWKSet keySet = JWKSet.parseJsonString(s);


    List<JWK> keyList = keySet.getKeys();
    expect(2, keyList.length);

    final bool publicParamsOnly = true;


    // Strip all private parameters
    s = JSON.encode(keySet.toJsonPublicKeysOnly(publicParamsOnly));

    keySet = JWKSet.parseJsonString(s);

    keyList = keySet.getKeys();
    expect(2, keyList.length);

    // Check first EC key
    JWK key = keyList[0];

    expectTrue(key is ECKey);
    expect("1", key.getKeyID());
    expect(KeyUse.ENCRYPTION, key.getKeyUse());
    expectNull(key.getKeyOperations());

    ECKey ecKey = key as ECKey;
    expect(ECKeyCurve.P_256, ecKey.getCurve());
    expect("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", ecKey.getX().toString());
    expect("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", ecKey.getY().toString());
    expectFalse(key.isPrivate());


    // Check second RSA key
    key = keyList[1];
    expectTrue(key is RSAKey);
    expect("2011-04-29", key.getKeyID());
    expectNull(key.getKeyUse());
    expectNull(key.getKeyOperations());
    expect(JWSAlgorithm.RS256, key.getAlgorithm());

    RSAKey rsaKey = key as RSAKey;
    expect("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
    "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
    "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
    "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
    "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
    "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    rsaKey.getModulus().toString());
    expect("AQAB", rsaKey.getPublicExponent().toString());
    expectFalse(key.isPrivate());
  });

  test('testGetByKeyId', () {

    // The string is from the JWK spec
    String s = "{\"keys\":" +
    "[" +
    "{\"kty\":\"EC\"," +
    "\"crv\":\"P-256\"," +
    "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"," +
    "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"," +
    "\"use\":\"enc\"," +
    "\"kid\":\"1\"}," +
    " " +
    "{\"kty\":\"RSA\"," +
    "\"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
    "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
    "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
    "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
    "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
    "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"," +
    "\"e\":\"AQAB\"," +
    "\"alg\":\"RS256\"," +
    "\"kid\":\"2011-04-29\"}" +
    "]" +
    "}";


    JWKSet keySet = JWKSet.parseJsonString(s);


    // Check first EC key
    JWK key = keySet.getKeyByKeyId("1");

    expectTrue(key is ECKey);
    expect("1", key.getKeyID());
    expect(KeyUse.ENCRYPTION, key.getKeyUse());

    ECKey ecKey = key as ECKey;
    expect(ECKeyCurve.P_256, ecKey.getCurve());
    expect("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", ecKey.getX().toString());
    expect("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", ecKey.getY().toString());
    expectFalse(key.isPrivate());


    // Check second RSA key
    key = keySet.getKeyByKeyId("2011-04-29");
    expectTrue(key is RSAKey);
    expect("2011-04-29", key.getKeyID());
    expectNull(key.getKeyUse());
    expectNull(key.getKeyOperations());
    expect(JWSAlgorithm.RS256, key.getAlgorithm());

    RSAKey rsaKey = key as RSAKey;
    expect("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
    "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
    "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
    "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
    "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
    "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    rsaKey.getModulus().toString());
    expect("AQAB", rsaKey.getPublicExponent().toString());
    expectFalse(key.isPrivate());
  });

  test('testOctJWKSetPublicExport', () {

    OctetSequenceKey oct1 = new OctetSequenceKeyBuilder(new Base64URL("abc")).build();
    expect("abc", oct1.getKeyValue().toString());

    OctetSequenceKey oct2 = new OctetSequenceKeyBuilder(new Base64URL("def")).build();
    expect("def", oct2.getKeyValue().toString());

    List<JWK> keyList = new List();
    keyList.add(oct1);
    keyList.add(oct2);

    JWKSet privateSet = new JWKSet.fromKeys(keyList);

    final bool publicParamsOnly = true;
    Map jsonObject = privateSet.toJsonPublicKeysOnly(publicParamsOnly);

    JWKSet publicSet = JWKSet.parseJsonString(JSON.encode(jsonObject));

    expect(0, publicSet.getKeys().length);
  });

  test('testOctJWKSetToPublic', () {

    OctetSequenceKey oct1 = new OctetSequenceKeyBuilder(new Base64URL("abc")).build();
    expect("abc", oct1.getKeyValue().toString());

    OctetSequenceKey oct2 = new OctetSequenceKeyBuilder(new Base64URL("def")).build();
    expect("def", oct2.getKeyValue().toString());

    List<JWK> keyList = new List();
    keyList.add(oct1);
    keyList.add(oct2);

    JWKSet privateSet = new JWKSet.fromKeys(keyList);

    JWKSet publicSet = privateSet.toPublicJWKSet();

    expect(0, publicSet.getKeys().length);
  });

  test('testMIMEType', () {

    expect("application/jwk-set+json; charset=UTF-8", JWKSet.MIME_TYPE);
  });

  test('testLoadFromFile', () {

    // The string is from the JWK spec
    String s = "{\"keys\":" +
    "[" +
    "{\"kty\":\"EC\"," +
    "\"crv\":\"P-256\"," +
    "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"," +
    "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"," +
    "\"use\":\"enc\"," +
    "\"kid\":\"1\"}," +
    " " +
    "{\"kty\":\"RSA\"," +
    "\"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
    "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
    "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
    "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
    "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
    "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"," +
    "\"e\":\"AQAB\"," +
    "\"alg\":\"RS256\"," +
    "\"kid\":\"2011-04-29\"}" +
    "]" +
    "}";

    File file = new File("TEST.jwkset.json");
    PrintWriter printWriter = new PrintWriter(file);
    printWriter.print(s);
    printWriter.close();

    JWKSet keySet = JWKSet.load(file);


    List<JWK> keyList = keySet.getKeys();
    expect(2, keyList.length);


    // Check first EC key
    JWK key = keyList[0];

    expectTrue(key is ECKey);
    expect("1", key.getKeyID());
    expect(KeyUse.ENCRYPTION, key.getKeyUse());

    ECKey ecKey = key as ECKey;
    expect(ECKeyCurve.P_256, ecKey.getCurve());
    expect("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", ecKey.getX().toString());
    expect("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", ecKey.getY().toString());
    expectFalse(key.isPrivate());


    // Check second RSA key
    key = keyList[1];
    expectTrue(key is RSAKey);
    expect("2011-04-29", key.getKeyID());
    expectNull(key.getKeyUse());
    expect(JWSAlgorithm.RS256, key.getAlgorithm());

    RSAKey rsaKey = key as RSAKey;
    expect("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
    "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
    "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
    "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
    "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
    "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    rsaKey.getModulus().toString());
    expect("AQAB", rsaKey.getPublicExponent().toString());
    expectFalse(key.isPrivate());

    Files.delete(file.toPath());
  });

  test('testLoadFromURL', () {

    initJadler();

    // The string is from the JWK spec
    String s = "{\"keys\":" +
    "[" +
    "{\"kty\":\"EC\"," +
    "\"crv\":\"P-256\"," +
    "\"x\":\"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\"," +
    "\"y\":\"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\"," +
    "\"use\":\"enc\"," +
    "\"kid\":\"1\"}," +
    " " +
    "{\"kty\":\"RSA\"," +
    "\"n\": \"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
    "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
    "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
    "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
    "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
    "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\"," +
    "\"e\":\"AQAB\"," +
    "\"alg\":\"RS256\"," +
    "\"kid\":\"2011-04-29\"}" +
    "]" +
    "}";

    onRequest()
    .havingMethodEqualTo("GET")
    .respond()
    .withStatus(200)
    .withBody(s)
    .withEncoding(Charset.forName("UTF-8"))
    .withContentType("application/json");

    JWKSet keySet = JWKSet.load(Uri.parse("http://localhost:" + port()));


    List<JWK> keyList = keySet.getKeys();
    expect(2, keyList.length);


    // Check first EC key
    JWK key = keyList[0];

    expectTrue(key is ECKey);
    expect("1", key.getKeyID());
    expect(KeyUse.ENCRYPTION, key.getKeyUse());

    ECKey ecKey = key as ECKey;
    expect(ECKeyCurve.P_256, ecKey.getCurve());
    expect("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", ecKey.getX().toString());
    expect("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM", ecKey.getY().toString());
    expectFalse(key.isPrivate());


    // Check second RSA key
    key = keyList[1];
    expectTrue(key is RSAKey);
    expect("2011-04-29", key.getKeyID());
    expectNull(key.getKeyUse());
    expect(JWSAlgorithm.RS256, key.getAlgorithm());

    RSAKey rsaKey = key as RSAKey;
    expect("0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx" +
    "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs" +
    "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2" +
    "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI" +
    "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb" +
    "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    rsaKey.getModulus().toString());
    expect("AQAB", rsaKey.getPublicExponent().toString());
    expectFalse(key.isPrivate());

    closeJadler();
  });

}

