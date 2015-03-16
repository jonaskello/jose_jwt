library jose_jwt.test.jwt_claims_set_test;

import 'dart:convert';
import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jwt.dart';
import 'package:jose_jwt/src/jose.dart';

/**
 * Tests JWT claims set serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @version $version$ (2015-02-13)
 */
//class JWTClaimsSetTest extends TestCase {
main() {

  test('testReservedNames', () {

    Set<String> names = JWTClaimsSet.getRegisteredNames();

    expect(names.contains("iss"), isTrue);
    expect(names.contains("sub"), isTrue);
    expect(names.contains("aud"), isTrue);
    expect(names.contains("exp"), isTrue);
    expect(names.contains("nbf"), isTrue);
    expect(names.contains("iat"), isTrue);
    expect(names.contains("jti"), isTrue);

    expect(7, equals(names.length));
  });

  test('testRun', () {
    JWTClaimsSet cs = new JWTClaimsSet();

    // JWT time claim precision is seconds
    final DateTime NOW = new DateTime.fromMillisecondsSinceEpoch(new DateTime.now().millisecondsSinceEpoch ~/ 1000 * 1000);

    // iss
    expect(cs.getIssuer(), isNull, reason: "iss init check");
    cs.setIssuer("http://issuer.com");
    expect("http://issuer.com", equals(cs.getIssuer()), reason: "iss set check");

    // sub
    expect(cs.getSubject(), isNull, reason: "sub init check");
    cs.setSubject("http://subject.com");
    expect("http://subject.com", equals(cs.getSubject()), reason: "sub set check");

    // aud
    expect(cs.getAudience(), isNull, reason: "aud init check");
    cs.setAudience("http://audience.com");
    expect("http://audience.com", equals(cs.getAudience()[0]), reason: "aud set check");

    // exp
    expect(cs.getExpirationTime(), isNull, reason: "exp init check");
    cs.setExpirationTime(NOW);
    expect(NOW, equals(cs.getExpirationTime()), reason: "exp set check");

    // nbf
    expect(cs.getNotBeforeTime(), isNull, reason: "nbf init check");
    cs.setNotBeforeTime(NOW);
    expect(NOW, equals(cs.getNotBeforeTime()), reason: "nbf set check");

    // iat
    expect(cs.getIssueTime(), isNull, reason: "iat init check");
    cs.setIssueTime(NOW);
    expect(NOW, equals(cs.getIssueTime()), reason: "iat set check");

    // jti
    expect(cs.getJWTID(), isNull, reason: "jti init check");
    cs.setJWTID("123");
    expect("123", equals(cs.getJWTID()), reason: "jti set check");

    // custom claims
    expect(cs.getCustomClaims().isEmpty, isTrue);

    // x-custom
    cs.setCustomClaim("x-custom", "abc");
    expect("abc", equals(cs.getCustomClaim("x-custom") as String));

    expect(1, equals(cs.getCustomClaims().length));

    // serialise
    Map json = cs.toJson();

    expect(8, equals(json.length));

    // parse back

//    try {
    cs = JWTClaimsSet.fromJson(json);

//    } catch (e) {
//      if (e is ParseError)
//        fail(e.message);
//			throw e;
//    }

    expect("http://issuer.com", equals(cs.getIssuer()), reason: "iss parse check");
    expect("http://subject.com", equals(cs.getSubject()), reason: "sub parse check");
    expect("http://audience.com", equals(cs.getAudience()[0]), reason: "aud parse check");
    expect(NOW, equals(cs.getExpirationTime()), reason: "exp parse check");
    expect(NOW, equals(cs.getNotBeforeTime()), reason: "nbf parse check");
    expect(NOW, equals(cs.getIssueTime()), reason: "iat parse check");
    expect("123", equals(cs.getJWTID()), reason: "jti parse check");
    expect("abc", equals(cs.getCustomClaim("x-custom") as String));
    expect(1, equals(cs.getCustomClaims().length));


    Map<String, Object> all = cs.getAllClaims();

    expect("http://issuer.com", equals(all["iss"] as String), reason: "iss parse check map");
    expect("http://subject.com", equals(all["sub"] as String), reason: "sub parse check map");
    expect("http://audience.com", equals((all["aud"] as List)[0] as String), reason: "aud parse check map");
    expect(NOW, equals(all["exp"]), reason: "exp parse check map");
    expect(NOW, equals(all["nbf"]), reason: "nbf parse check map");
    expect(NOW, equals(all["iat"]), reason: "iat parse check map");
    expect("123", equals(all["jti"] as String), reason: "jti parse check map");
    expect("abc", equals(all["x-custom"] as String));

  });

  test('testClaimsPassthrough', () {


    JWTClaimsSet cs = new JWTClaimsSet();

    // reserved issuer claim
    // iss
    expect(cs.getIssuer(), isNull, reason: "iss init check");
    cs.setClaim("iss", "http://issuer.com");
    expect("http://issuer.com", equals(cs.getClaim("iss")), reason: "iss set check");
    expect("http://issuer.com", equals(cs.getIssuer()), reason:"iss set check");

    // custom claim
    expect(cs.getClaim("x-custom"), isNull, reason:"x-custom init check");
    cs.setClaim("x-custom", "abc");
    expect("abc", equals(cs.getClaim("x-custom") as String));

    // serialise
    Map json = cs.toJson();

    expect(2, equals(json.length));

    // parse back

//    try {
    cs = JWTClaimsSet.fromJson(json);

//    } catch (e) {
//      if (e is ParseError)
//        fail(e.getMessage());
//    }

    expect("http://issuer.com", equals(cs.getClaim("iss")), reason: "iss set check");
    expect("http://issuer.com", equals(cs.getIssuer()), reason:"iss set check");
    expect(cs.getClaim("x-custom") as String, equals("abc"));


  });

  test('testDateConversion', () {

    JWTClaimsSet cs = new JWTClaimsSet();

    final DateTime ONE_MIN_AFTER_EPOCH = new DateTime.fromMillisecondsSinceEpoch (1000 * 60);

    cs.setIssueTime(ONE_MIN_AFTER_EPOCH);
    cs.setNotBeforeTime(ONE_MIN_AFTER_EPOCH);
    cs.setExpirationTime(ONE_MIN_AFTER_EPOCH);

    Map json = cs.toJson();

    expect(60, equals(json["iat"]));
    expect(60, equals(json["nbf"]));
    expect(60, equals(json["exp"]));

  });

  test('testSetCustomClaimsNull', () {

    JWTClaimsSet cs = new JWTClaimsSet();

    cs.setCustomClaim("locale", "bg-BG");

    expect(1, equals(cs.getCustomClaims().length));

    cs.setCustomClaims(null);

    expect(cs.getCustomClaims().isEmpty, isTrue);
  });

  test('testSetCustomClaimsEmpty', () {

    JWTClaimsSet cs = new JWTClaimsSet();

    cs.setCustomClaim("locale", "bg-BG");

    expect(1, equals(cs.getCustomClaims().length));

    cs.setCustomClaims(new Map<String, Object>());

    expect(cs.getCustomClaims().isEmpty, isTrue);
  });

  test('testSetCustomClaims', () {

    JWTClaimsSet cs = new JWTClaimsSet();

    cs.setCustomClaim("locale", "bg-BG");

    expect(1, equals(cs.getCustomClaims().length));

    Map<String, Object> newCustomClaims = new Map();
    newCustomClaims["locale"] = "es-ES";
    newCustomClaims["ip"] = "127.0.0.1";

    cs.setCustomClaims(newCustomClaims);

    expect(2, equals(cs.getCustomClaims().length));

    expect("es-ES", equals(cs.getCustomClaims()["locale"] as String));
    expect("127.0.0.1", equals(cs.getCustomClaims()["ip"] as String));
  });


  test('testGetClaimValueNotSpecified', () {

    JWTClaimsSet cs = new JWTClaimsSet();

    expect(cs.getClaim("xyz"), isNull);
  });


  test('testSetClaimNull', () {

    JWTClaimsSet cs = new JWTClaimsSet();

    cs.setIssuer("http://example.com");
    expect("http://example.com", equals(cs.getIssuer()));
    cs.setClaim("iss", null);
    expect(cs.getIssuer(), isNull);

    cs.setSubject("alice");
    expect("alice", equals(cs.getSubject()));
    cs.setClaim("sub", null);
    expect(cs.getSubject(), isNull);

    List<String> audList = new List();
    audList.add("http://client.example.com");
    cs.setAudienceList(audList);
    expect("http://client.example.com", equals(cs.getAudience()[0]));
    cs.setClaim("aud", null);
    expect(cs.getAudience(), isNull);

    DateTime now = new DateTime.now();
    cs.setExpirationTime(now);
    expect(now, equals(cs.getExpirationTime()));
    cs.setClaim("exp", null);
    expect(cs.getExpirationTime(), isNull);

    cs.setNotBeforeTime(now);
    expect(now, equals(cs.getNotBeforeTime()));
    cs.setClaim("nbf", null);
    expect(cs.getNotBeforeTime(), isNull);

    cs.setIssueTime(now);
    expect(now, equals(cs.getIssueTime()));
    cs.setClaim("iat", null);
    expect(cs.getIssueTime(), isNull);

    cs.setJWTID("123");
    expect("123", equals(cs.getJWTID()));
    cs.setClaim("jti", null);
    expect(cs.getJWTID(), isNull);
  });


  test('testGetClaimTyped', () {

    JWTClaimsSet cs = new JWTClaimsSet();

    cs.setClaim("string", "abc");
    expect("abc", equals(cs.getStringClaim("string")));

    cs.setClaim("boolean", false);
    expect(cs.getBooleanClaim("boolean"), isFalse);

    cs.setClaim("integer", 123);
    expect(123, equals(cs.getIntegerClaim("integer").toInt()));

//    cs.setClaim("long", 456);
//    expect(456, equals(cs.getLongClaim("long").longValue()));
//
//    cs.setClaim("float", 3.14);
//    expect(3.14, equals(cs.getFloatClaim("float").floatValue()));

    cs.setClaim("double", 3.14);
    expect(3.14, equals(cs.getDoubleClaim("double").toDouble()));
  });


  test('testGetClaimTypedNull', () {

    JWTClaimsSet cs = new JWTClaimsSet();

    cs.setClaim("string", null);
    expect(cs.getStringClaim("string"), isNull);

    cs.setClaim("boolean", null);
    expect(cs.getBooleanClaim("boolean"), isNull);

    cs.setClaim("integer", null);
    expect(cs.getIntegerClaim("integer"), isNull);

//		cs.setClaim("long", null);
//    expect(cs.getLongClaim("long"), isNull);
//
//		cs.setClaim("float", null);
//    expect(cs.getFloatClaim("float"), isNull);

    cs.setClaim("double", null);
    expect(cs.getDoubleClaim("double"), isNull);
  });


  test('testGetClaimTypedParseError', () {

    JWTClaimsSet cs = new JWTClaimsSet();

    cs.setClaim("string", 3.14);
    expect(() => cs.getStringClaim("string"), throwsA(new isInstanceOf<ParseError>()));

    cs.setClaim("boolean", "123");
    expect(() => cs.getBooleanClaim("boolean"), throwsA(new isInstanceOf<ParseError>()));

    cs.setClaim("integer", true);
    expect(() => cs.getIntegerClaim("integer"), throwsA(new isInstanceOf<ParseError>()));

    cs.setClaim("double", "abc");
    expect(() => cs.getDoubleClaim("double"), throwsA(new isInstanceOf<ParseError>()));
  });

  test('testStringAudience', () {

    Map o = new Map();
    o["aud"] = "http://example.com";

    ReadOnlyJWTClaimsSet jwtClaimsSet = JWTClaimsSet.fromJsonString(JSON.encode(o));

    expect("http://example.com", equals(jwtClaimsSet.getAudience()[0]));
    expect(1, equals(jwtClaimsSet.getAudience().length));
  });


  test('testStringArrayAudience', () {

    Map o = new Map();
    o["aud"] = ["http://example.com"];

    ReadOnlyJWTClaimsSet jwtClaimsSet = JWTClaimsSet.fromJsonString(JSON.encode(o));

    expect("http://example.com", equals(jwtClaimsSet.getAudience()[0]));
    expect(1, equals(jwtClaimsSet.getAudience().length));
  });

  test('testStringArrayMultipleAudience', () {

    Map o = new Map();
    o["aud"] = ["http://example.com", "http://example2.com"];

    ReadOnlyJWTClaimsSet jwtClaimsSet = JWTClaimsSet.fromJsonString(JSON.encode(o));

    expect("http://example.com", equals(jwtClaimsSet.getAudience()[0]));
    expect("http://example2.com", equals(jwtClaimsSet.getAudience()[1]));
    expect(2, jwtClaimsSet.getAudience().length);
  });

  test('testParseExampleIDToken', () {

    String json = "{\"exp\":1384798159,\"sub\":\"alice\",\"aud\":[\"000001\"],\"iss\":\"https:\\/\\/localhost:8080\\/c2id\",\"login_geo\":{\"long\":\"37.3956\",\"lat\":\"-122.076\"},\"login_ip\":\"185.7.248.1\",\"iat\":1384797259,\"acr\":\"urn:mace:incommon:iap:silver\",\"c_hash\":\"vwVj99I7FizReIt5q3UwhQ\",\"amr\":[\"mfa\"]}";

    JWTClaimsSet claimsSet = JWTClaimsSet.fromJsonString(json);

    expect(1384798159, equals(claimsSet.getExpirationTime().millisecondsSinceEpoch ~/ 1000));
    expect(1384797259, equals(claimsSet.getIssueTime().millisecondsSinceEpoch ~/ 1000));

    expect("alice", equals(claimsSet.getSubject()));

    expect("000001", equals(claimsSet.getAudience()[0]));
    expect(1, equals(claimsSet.getAudience().length));

    expect("https://localhost:8080/c2id", equals(claimsSet.getIssuer()));
    expect("urn:mace:incommon:iap:silver", equals(claimsSet.getStringClaim("acr")));

    expect("vwVj99I7FizReIt5q3UwhQ", equals(claimsSet.getStringClaim("c_hash")));

    expect("mfa", equals((claimsSet.getCustomClaim("amr") as List<String>)[0]));
    expect(1, equals((claimsSet.getCustomClaim("amr") as List<String>).length));

    expect("185.7.248.1", equals(claimsSet.getStringClaim("login_ip")));

    Map geoLoc = claimsSet.getCustomClaim("login_geo") as Map;

    // {"long":"37.3956","lat":"-122.076"}
    expect("37.3956", equals(geoLoc["long"] as String));
    expect("-122.076", equals(geoLoc["lat"] as String));
  });

  test('testSingleValuedAudienceSetter', () {

    JWTClaimsSet claimsSet = new JWTClaimsSet();
    expect(claimsSet.getAudience(), isNull);

    claimsSet.setAudience("123");
    expect("123", equals(claimsSet.getAudience()[0]));
    expect(1, equals(claimsSet.getAudience().length));

    claimsSet.setAudience(null);
    expect(claimsSet.getAudience(), isNull);
  });

  test('testSerializeSingleValuedAudience', () {

    JWTClaimsSet claimsSet = new JWTClaimsSet();
    claimsSet.setAudience("123");

    Map json = claimsSet.toJson();

    expect("123", equals(json["aud"] as String));
    expect(1, equals(json.length));

    claimsSet = JWTClaimsSet.fromJsonString(JSON.encode(json));
    expect("123", equals(claimsSet.getAudience()[0]));
    expect(1, equals(claimsSet.getAudience().length));
  });

  test('testGetAllClaimsEmpty', () {

    JWTClaimsSet claimsSet = new JWTClaimsSet();
    expect(claimsSet.getAllClaims().isEmpty, isTrue);
  });

  test('testParseOIDCAuthz', () {

    String json = "{\"sub\":\"alice\",\"irt\":true,\"rft\":\"YWxpY2U.aHR0cDovL2NsaWVudDEuZXhhbXBsZS5jb20.rsKHqBpyEh-MMtllO7chHg\",\"aud\":[\"http:\\/\\/userinfo.example.com\"],\"iss\":\"http:\\/\\/oidc.example.com\",\"ate\":\"IDENTIFIER\",\"lng\":true,\"iat\":1420544052,\"cid\":\"http:\\/\\/client1.example.com\"}";
    JWTClaimsSet.fromJsonString(json);
  });


  test('testAudienceParsing', () {

    Map json = new Map();
    List aud = new List();
    aud.add("client-1");
    aud.add("client-2");
    json["aud"] = aud;

    JWTClaimsSet claimsSet = JWTClaimsSet.fromJson(json);
    expect("client-1", equals(claimsSet.getAudience()[0]));
    expect("client-2", equals(claimsSet.getAudience()[1]));
    expect(2, equals(claimsSet.getAudience().length));
  });


  test('testGetStringArrayClaim', () {

    Map json = new Map();
    List jsonArray = new List();
    jsonArray.add("client-1");
    jsonArray.add("client-2");
    json["array"] = jsonArray;

    JWTClaimsSet claimsSet = JWTClaimsSet.fromJson(json);

    List<String> strings = claimsSet.getStringArrayClaim("array");
    expect("client-1", equals(strings[0]));
    expect("client-2", equals(strings[1]));
    expect(2, equals(strings.length));
  });

  test('testGetInvalidStringArrayClaim', () {

    Map jsonObject = new Map();
    List jsonArray = new List();
    jsonArray.add("client-1");
    jsonArray.add(0);
    jsonObject["array"] = jsonArray;

    JWTClaimsSet claimsSet = JWTClaimsSet.fromJson(jsonObject);

//    try {
    expect(() => claimsSet.getStringArrayClaim("array"), throwsA(new isInstanceOf<ParseError>()));
//      fail();
//    } catch (e) {
//      if (e is ParseError) throw e; else throw e;
//      // ok
//    }
  });

  test('testGetNullStringArrayClaim', () {

    Map json = new Map();

    JWTClaimsSet claimsSet = JWTClaimsSet.fromJson(json);

    expect(claimsSet.getStringArrayClaim("array"), isNull);
  });

  test('testGetStringListClaim', () {

    Map json = new Map();
    List jsonArray = new List();
    jsonArray.add("client-1");
    jsonArray.add("client-2");
    json["array"] = jsonArray;

    JWTClaimsSet claimsSet = JWTClaimsSet.fromJson(json);

    List<String> strings = claimsSet.getStringListClaim("array");
    expect("client-1", equals(strings[0]));
    expect("client-2", equals(strings[1]));
    expect(2, equals(strings.length));
  });


  test('testGetInvalidStringListClaim', () {

    Map json = new Map();
    List jsonArray = new List();
    jsonArray.add("client-1");
    jsonArray.add(0);
    json["array"] = jsonArray;

    JWTClaimsSet claimsSet = JWTClaimsSet.fromJson(json);

//    try {
    expect(() => claimsSet.getStringListClaim("array"), throwsA(new isInstanceOf<ParseError>()));
//    fail();
//    } catch (e) {
//      if (e is ParseError) throw e; else throw e;
//      // ok
//    }
  });


  test('testGetNullStringListClaim', () {

    Map json = new Map();

    JWTClaimsSet claimsSet = JWTClaimsSet.fromJson(json);

    expect(claimsSet.getStringListClaim("array"), isNull);
  });

  test('testExtendedCyrillicChars', () {

    JWTClaimsSet claimsSet = new JWTClaimsSet();
    claimsSet.setSubject("Владимир Джувинов");

    String json = JSON.encode(claimsSet.toJson());

    claimsSet = JWTClaimsSet.fromJsonString(json);

    expect("Владимир Джувинов", equals(claimsSet.getSubject()));
  });

  test('testExtendedLatinChars', () {

    JWTClaimsSet claimsSet = new JWTClaimsSet();
    claimsSet.setClaim("fullName", "João");

    String json = JSON.encode(claimsSet.toJson());

    Base64URL base64URL = Base64URL.encodeString(json);

    claimsSet = JWTClaimsSet.fromJsonString(base64URL.decodeToString());

    expect("João", equals(claimsSet.getStringClaim("fullName")));
  });

}
