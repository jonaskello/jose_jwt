library jose_jwt.test.jwt_claims_set_test;

import 'dart:typed_data';
import 'package:unittest/unittest.dart';
import 'package:cipher/cipher.dart';
import 'package:cipher/impl/server.dart';
import 'package:bignum/bignum.dart';
import 'package:jose_jwt/src/jwt.dart';
import 'package:jose_jwt/src/jose.dart';
import 'package:jose_jwt/src/crypto.dart';

/**
 * Tests JWT claims set serialisation and parsing.
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @version $version$ (2015-02-13)
 */
//class JWTClaimsSetTest extends TestCase {
main() {

//	void testReservedNames() {
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
//	}
  });


//	public void testRun() {
  test('testRun', () {
    JWTClaimsSet cs = new JWTClaimsSet();

    // JWT time claim precision is seconds
    final DateTime NOW = new DateTime(new DateTime.now().millisecondsSinceEpoch ~/ 1000 * 1000);

    // iss
    expect("iss init check", cs.getIssuer(), isNull);
    cs.setIssuer("http://issuer.com");
    expect("http://issuer.com", equals(cs.getIssuer()), reason: "iss set check");

    // sub
    expectNull("sub init check", cs.getSubject());
    cs.setSubject("http://subject.com");
    expect("sub set check", "http://subject.com", equals(cs.getSubject()));

    // aud
    expectNull("aud init check", cs.getAudience());
    cs.setAudience(Arrays.asList("http://audience.com"));
    expect("aud set check", "http://audience.com", equals(cs.getAudience().get(0)));

    // exp
    expectNull("exp init check", cs.getExpirationTime());
    cs.setExpirationTime(NOW);
    expect("exp set check", NOW, equals(cs.getExpirationTime()));

    // nbf
    expectNull("nbf init check", cs.getNotBeforeTime());
    cs.setNotBeforeTime(NOW);
    expect("nbf set check", NOW, equals(cs.getNotBeforeTime()));

    // iat
    expectNull("iat init check", cs.getIssueTime());
    cs.setIssueTime(NOW);
    expect("iat set check", NOW, equals(cs.getIssueTime()));

    // jti
    expectNull("jti init check", cs.getJWTID());
    cs.setJWTID("123");
    expect("jti set check", "123", equals(cs.getJWTID()));
/*

		// custom claims
		expectTrue(cs.getCustomClaims().isEmpty());

		// x-custom
		cs.setCustomClaim("x-custom", "abc");
		expectEquals("abc", (String)cs.getCustomClaim("x-custom"));

		expectEquals(1, cs.getCustomClaims().size());


		// serialise
		JSONObject json = cs.toJSONObject();

		expectEquals(8, json.size());

		// parse back

		try {
			cs = JWTClaimsSet.parse(json);

		} catch ( e) {
if(e is ParseException)
			fail(e.getMessage());
		}

		expectEquals("iss parse check", "http://issuer.com", cs.getIssuer());
		expectEquals("sub parse check", "http://subject.com", cs.getSubject());
		expectEquals("aud parse check", "http://audience.com", cs.getAudience().get(0));
		expectEquals("exp parse check", NOW, cs.getExpirationTime());
		expectEquals("nbf parse check", NOW, cs.getNotBeforeTime());
		expectEquals("iat parse check", NOW, cs.getIssueTime());
		expectEquals("jti parse check", "123", cs.getJWTID());
		expectEquals("abc", (String)cs.getCustomClaim("x-custom"));
		expectEquals(1, cs.getCustomClaims().size());


		Map<String,Object> all = cs.getAllClaims();

		expectEquals("iss parse check map", "http://issuer.com", (String)all.get("iss"));
		expectEquals("sub parse check map", "http://subject.com", (String)all.get("sub"));
		expectEquals("aud parse check map", "http://audience.com", (String)((List)all.get("aud")).get(0));
		expectEquals("exp parse check map", NOW, all.get("exp"));
		expectEquals("nbf parse check map", NOW, all.get("nbf"));
		expectEquals("iat parse check map", NOW, all.get("iat"));
		expectEquals("jti parse check map", "123", (String)all.get("jti"));
		expectEquals("abc", (String)all.get("x-custom"));
//	}
*/
  });


/*
	public void testClaimsPassthrough() {

		JWTClaimsSet cs = new JWTClaimsSet();

		// reserved issuer claim
		// iss
		expectNull("iss init check", cs.getIssuer());
		cs.setClaim("iss", "http://issuer.com");
		expectEquals("iss set check", "http://issuer.com", cs.getClaim("iss"));
		expectEquals("iss set check", "http://issuer.com", cs.getIssuer());

		// custom claim
		expectNull("x-custom init check", cs.getClaim("x-custom"));
		cs.setClaim("x-custom", "abc");
		expectEquals("abc", (String)cs.getClaim("x-custom"));

		// serialise
		JSONObject json = cs.toJSONObject();

		expectEquals(2, json.size());

		// parse back

		try {
			cs = JWTClaimsSet.parse(json);

		} catch (java.text.ParseException e) {

			fail(e.getMessage());
		}

		expectEquals("iss set check", "http://issuer.com", cs.getClaim("iss"));
		expectEquals("iss set check", "http://issuer.com", cs.getIssuer());
		expectEquals("abc", (String)cs.getClaim("x-custom"));
	}


	public void testDateConversion() {

		JWTClaimsSet cs = new JWTClaimsSet();

		final Date ONE_MIN_AFTER_EPOCH = new Date(1000*60);

		cs.setIssueTime(ONE_MIN_AFTER_EPOCH);
		cs.setNotBeforeTime(ONE_MIN_AFTER_EPOCH);
		cs.setExpirationTime(ONE_MIN_AFTER_EPOCH);

		JSONObject json = cs.toJSONObject();

		expectEquals(new Long(60l), json.get("iat"));
		expectEquals(new Long(60l), json.get("nbf"));
		expectEquals(new Long(60l), json.get("exp"));
	}
	
	
	public void testSetCustomClaimsNull() {
		
		JWTClaimsSet cs = new JWTClaimsSet();
		
		cs.setCustomClaim("locale", "bg-BG");
		
		expectEquals(1, cs.getCustomClaims().size());
		
		cs.setCustomClaims(null);
		
		expectTrue(cs.getCustomClaims().isEmpty());
	}
	
	
	public void testSetCustomClaimsEmpty() {
		
		JWTClaimsSet cs = new JWTClaimsSet();
		
		cs.setCustomClaim("locale", "bg-BG");
		
		expectEquals(1, cs.getCustomClaims().size());
		
		cs.setCustomClaims(new HashMap<String,Object>());
		
		expectTrue(cs.getCustomClaims().isEmpty());
	}
	
	
	public void testSetCustomClaims() {
		
		JWTClaimsSet cs = new JWTClaimsSet();
		
		cs.setCustomClaim("locale", "bg-BG");
		
		expectEquals(1, cs.getCustomClaims().size());
		
		Map<String,Object> newCustomClaims = new HashMap<>();
		newCustomClaims.put("locale", "es-ES");
		newCustomClaims.put("ip", "127.0.0.1");
		
		cs.setCustomClaims(newCustomClaims);
		
		expectEquals(2, cs.getCustomClaims().size());
		
		expectEquals("es-ES", (String)cs.getCustomClaims().get("locale"));
		expectEquals("127.0.0.1", (String)cs.getCustomClaims().get("ip"));
	}
	
	
	public void testGetClaimValueNotSpecified() {
		
		JWTClaimsSet cs = new JWTClaimsSet();
		
		expectNull(cs.getClaim("xyz"));
	}
	
	
	public void testSetClaimNull() {
		
		JWTClaimsSet cs = new JWTClaimsSet();
		
		cs.setIssuer("http://example.com");
		expectEquals("http://example.com", cs.getIssuer());
		cs.setClaim("iss", null);
		expectNull(cs.getIssuer());
		
		cs.setSubject("alice");
		expectEquals("alice", cs.getSubject());
		cs.setClaim("sub", null);
		expectNull(cs.getSubject());
		
		List<String> audList = new ArrayList<>();
		audList.add("http://client.example.com");
		cs.setAudience(audList);
		expectEquals("http://client.example.com", cs.getAudience().get(0));
		cs.setClaim("aud", null);
		expectNull(cs.getAudience());
		
		Date now = new Date();
		cs.setExpirationTime(now);
		expectEquals(now, cs.getExpirationTime());
		cs.setClaim("exp", null);
		expectNull(cs.getExpirationTime());
		
		cs.setNotBeforeTime(now);
		expectEquals(now, cs.getNotBeforeTime());
		cs.setClaim("nbf", null);
		expectNull(cs.getNotBeforeTime());
		
		cs.setIssueTime(now);
		expectEquals(now, cs.getIssueTime());
		cs.setClaim("iat", null);
		expectNull(cs.getIssueTime());
		
		cs.setJWTID("123");
		expectEquals("123", cs.getJWTID());
		cs.setClaim("jti", null);
		expectNull(cs.getJWTID());
	}
	
	
	public void testGetClaimTyped()
		throws Exception {
		
		JWTClaimsSet cs = new JWTClaimsSet();
		
		cs.setClaim("string", "abc");
		expectEquals("abc", cs.getStringClaim("string"));
		
		cs.setClaim("boolean", false);
		expectFalse(cs.getBooleanClaim("boolean"));
		
		cs.setClaim("integer", 123);
		expectEquals(123, cs.getIntegerClaim("integer").intValue());
		
		cs.setClaim("long", 456l);
		expectEquals(456l, cs.getLongClaim("long").longValue());
		
		cs.setClaim("float", 3.14f);
		expectEquals(3.14f, cs.getFloatClaim("float").floatValue());
		
		cs.setClaim("double", 3.14d);
		expectEquals(3.14d, cs.getDoubleClaim("double").doubleValue());
	}
	
	
	public void testGetClaimTypedNull()
		throws Exception {
		
		JWTClaimsSet cs = new JWTClaimsSet();
		
		cs.setClaim("string", null);
		expectNull(cs.getStringClaim("string"));
		
		cs.setClaim("boolean", null);
		expectNull(cs.getBooleanClaim("boolean"));
		
		cs.setClaim("integer", null);
		expectNull(cs.getIntegerClaim("integer"));
		
		cs.setClaim("long", null);
		expectNull(cs.getLongClaim("long"));
		
		cs.setClaim("float", null);
		expectNull(cs.getFloatClaim("float"));
		
		cs.setClaim("double", null);
		expectNull(cs.getDoubleClaim("double"));
	}
	
	
	public void testGetClaimTypedParseException() {
		
		JWTClaimsSet cs = new JWTClaimsSet();
		
		cs.setClaim("string", 3.14);
		
		try {
			cs.getStringClaim("string");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
		
		cs.setClaim("boolean", "123");
		
		try {
			cs.getBooleanClaim("boolean");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
		
		cs.setClaim("integer", true);
		
		try {
			cs.getIntegerClaim("integer");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
		
		cs.setClaim("long", "abc");
		
		try {
			cs.getLongClaim("long");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
		
		cs.setClaim("float", true);
		
		try {
			cs.getFloatClaim("float");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
		
		cs.setClaim("double", "abc");
		
		try {
			cs.getDoubleClaim("double");
			
			fail("Failed to raise exception");
			
		} catch (ParseException e) {
			// ok
		}
	}


	public void testStringAudience()
		throws Exception {

		JSONObject o = new JSONObject();
		o.put("aud", "http://example.com");

		ReadOnlyJWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(o.toJSONString());

		expectEquals("http://example.com", jwtClaimsSet.getAudience().get(0));
		expectEquals(1, jwtClaimsSet.getAudience().size());
	}


	public void testStringArrayAudience()
		throws Exception {

		JSONObject o = new JSONObject();
		o.put("aud", Arrays.asList("http://example.com"));

		ReadOnlyJWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(o.toJSONString());

		expectEquals("http://example.com", jwtClaimsSet.getAudience().get(0));
		expectEquals(1, jwtClaimsSet.getAudience().size());
	}


	public void testStringArrayMultipleAudience()
		throws Exception {

		JSONObject o = new JSONObject();
		o.put("aud", Arrays.asList("http://example.com", "http://example2.com"));

		ReadOnlyJWTClaimsSet jwtClaimsSet = JWTClaimsSet.parse(o.toJSONString());

		expectEquals("http://example.com", jwtClaimsSet.getAudience().get(0));
		expectEquals("http://example2.com", jwtClaimsSet.getAudience().get(1));
		expectEquals(2, jwtClaimsSet.getAudience().size());
	}


	public void testParseExampleIDToken()
		throws Exception {

		String json = "{\"exp\":1384798159,\"sub\":\"alice\",\"aud\":[\"000001\"],\"iss\":\"https:\\/\\/localhost:8080\\/c2id\",\"login_geo\":{\"long\":\"37.3956\",\"lat\":\"-122.076\"},\"login_ip\":\"185.7.248.1\",\"iat\":1384797259,\"acr\":\"urn:mace:incommon:iap:silver\",\"c_hash\":\"vwVj99I7FizReIt5q3UwhQ\",\"amr\":[\"mfa\"]}";

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(json);

		expectEquals(1384798159l, claimsSet.getExpirationTime().getTime() / 1000);
		expectEquals(1384797259l, claimsSet.getIssueTime().getTime() / 1000);

		expectEquals("alice", claimsSet.getSubject());

		expectEquals("000001", claimsSet.getAudience().get(0));
		expectEquals(1, claimsSet.getAudience().size());

		expectEquals("https://localhost:8080/c2id", claimsSet.getIssuer());

		expectEquals("urn:mace:incommon:iap:silver", claimsSet.getStringClaim("acr"));

		expectEquals("vwVj99I7FizReIt5q3UwhQ", claimsSet.getStringClaim("c_hash"));

		expectEquals("mfa", ((List<String>)claimsSet.getCustomClaim("amr")).get(0));
		expectEquals(1, ((List<String>)claimsSet.getCustomClaim("amr")).size());

		expectEquals("185.7.248.1", claimsSet.getStringClaim("login_ip"));

		JSONObject geoLoc = (JSONObject)claimsSet.getCustomClaim("login_geo");

		// {"long":"37.3956","lat":"-122.076"}
		expectEquals("37.3956", (String)geoLoc.get("long"));
		expectEquals("-122.076", (String)geoLoc.get("lat"));
	}


	public void testSingleValuedAudienceSetter() {

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		expectNull(claimsSet.getAudience());

		claimsSet.setAudience("123");
		expectEquals("123", claimsSet.getAudience().get(0));
		expectEquals(1, claimsSet.getAudience().size());

		claimsSet.setAudience((String) null);
		expectNull(claimsSet.getAudience());
	}


	public void testSerializeSingleValuedAudience()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setAudience("123");

		JSONObject jsonObject = claimsSet.toJSONObject();

		expectEquals("123", (String)jsonObject.get("aud"));
		expectEquals(1, jsonObject.size());

		claimsSet = JWTClaimsSet.parse(jsonObject.toJSONString());
		expectEquals("123", claimsSet.getAudience().get(0));
		expectEquals(1, claimsSet.getAudience().size());
	}


	public void testGetAllClaimsEmpty() {

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		expectTrue(claimsSet.getAllClaims().isEmpty());
	}


	public void testParseOIDCAuthz()
		throws Exception {

		String json = "{\"sub\":\"alice\",\"irt\":true,\"rft\":\"YWxpY2U.aHR0cDovL2NsaWVudDEuZXhhbXBsZS5jb20.rsKHqBpyEh-MMtllO7chHg\",\"aud\":[\"http:\\/\\/userinfo.example.com\"],\"iss\":\"http:\\/\\/oidc.example.com\",\"ate\":\"IDENTIFIER\",\"lng\":true,\"iat\":1420544052,\"cid\":\"http:\\/\\/client1.example.com\"}";
		JWTClaimsSet.parse(json);
	}


	public void testAudienceParsing()
		throws Exception {

		JSONObject jsonObject = new JSONObject();
		JSONArray aud = new JSONArray();
		aud.add("client-1");
		aud.add("client-2");
		jsonObject.put("aud", aud);

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(jsonObject);
		expectEquals("client-1", claimsSet.getAudience().get(0));
		expectEquals("client-2", claimsSet.getAudience().get(1));
		expectEquals(2, claimsSet.getAudience().size());
	}


	public void testGetStringArrayClaim()
		throws Exception {

		JSONObject jsonObject = new JSONObject();
		JSONArray jsonArray = new JSONArray();
		jsonArray.add("client-1");
		jsonArray.add("client-2");
		jsonObject.put("array", jsonArray);

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(jsonObject);

		String[] strings = claimsSet.getStringArrayClaim("array");
		expectEquals("client-1", strings[0]);
		expectEquals("client-2", strings[1]);
		expectEquals(2, strings.length);
	}


	public void testGetInvalidStringArrayClaim()
		throws Exception {

		JSONObject jsonObject = new JSONObject();
		JSONArray jsonArray = new JSONArray();
		jsonArray.add("client-1");
		jsonArray.add(0);
		jsonObject.put("array", jsonArray);

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(jsonObject);

		try {
			claimsSet.getStringArrayClaim("array");
			fail();
		} catch (ParseException e) {
			// ok
		}
	}


	public void testGetNullStringArrayClaim()
		throws Exception {

		JSONObject jsonObject = new JSONObject();

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(jsonObject);

		expectNull(claimsSet.getStringArrayClaim("array"));
	}


	public void testGetStringListClaim()
		throws Exception {

		JSONObject jsonObject = new JSONObject();
		JSONArray jsonArray = new JSONArray();
		jsonArray.add("client-1");
		jsonArray.add("client-2");
		jsonObject.put("array", jsonArray);

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(jsonObject);

		List<String> strings = claimsSet.getStringListClaim("array");
		expectEquals("client-1", strings.get(0));
		expectEquals("client-2", strings.get(1));
		expectEquals(2, strings.size());
	}


	public void testGetInvalidStringListClaim()
		throws Exception {

		JSONObject jsonObject = new JSONObject();
		JSONArray jsonArray = new JSONArray();
		jsonArray.add("client-1");
		jsonArray.add(0);
		jsonObject.put("array", jsonArray);

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(jsonObject);

		try {
			claimsSet.getStringListClaim("array");
			fail();
		} catch (ParseException e) {
			// ok
		}
	}


	public void testGetNullStringListClaim()
		throws Exception {

		JSONObject jsonObject = new JSONObject();

		JWTClaimsSet claimsSet = JWTClaimsSet.parse(jsonObject);

		expectNull(claimsSet.getStringListClaim("array"));
	}


	public void testExtendedCyrillicChars()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setSubject("Владимир Джувинов");

		String json = claimsSet.toJSONObject().toJSONString();

		claimsSet = JWTClaimsSet.parse(json);

		expectEquals("Владимир Джувинов", claimsSet.getSubject());
	}


	public void testExtendedLatinChars()
		throws Exception {

		JWTClaimsSet claimsSet = new JWTClaimsSet();
		claimsSet.setClaim("fullName", "João");

		String json = claimsSet.toJSONObject().toJSONString();

		Base64URL base64URL = Base64URL.encode(json);

		claimsSet = JWTClaimsSet.parse(base64URL.decodeToString());

		expectEquals("João", claimsSet.getStringClaim("fullName"));
	}

}

*/

}
