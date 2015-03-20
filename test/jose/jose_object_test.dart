library jose_jwt.test.jose.jose_object_test;

import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jose.dart';


/**
 * Tests JOSE object methods.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-02-04)
 */
//public class JOSEObjectTest extends TestCase {
main() {

  test('testSplitThreeParts', () {

    // Implies JWS
    String s = "abc.def.ghi";

    List<Base64URL> parts = null;

//		try {
    parts = JOSEObject.split(s);

//		} catch (ParseException e) {
//
//			fail(e.getMessage());
//		}

    expect(3, parts.length);

    expect("abc", parts[0].toString());
    expect("def", parts[1].toString());
    expect("ghi", parts[2].toString());
  });


  test('testSplitFiveParts', () {

    // Implies JWE
    String s = "abc.def.ghi.jkl.mno";

    List<Base64URL> parts = null;

//		try {
    parts = JOSEObject.split(s);

//		} catch (ParseException e) {
//
//			fail(e.getMessage());
//		}

    expect(5, parts.length);

    expect("abc", parts[0].toString());
    expect("def", parts[1].toString());
    expect("ghi", parts[2].toString());
    expect("jkl", parts[3].toString());
    expect("mno", parts[4].toString());
  });


  test('testSplitEmptyThirdPart', () {

    // Implies plain JOSE object
    String s = "abc.def.";

    List<Base64URL> parts = null;

//		try {
    parts = JOSEObject.split(s);

//		} catch (ParseException e) {
//
//			fail(e.getMessage());
//		}

    expect(3, parts.length);

    expect("abc", parts[0].toString());
    expect("def", parts[1].toString());
    expect("", parts[2].toString());
  });


  test('testSplitEmptySecondPart', () {

    // JWS with empty payload
    String s = "abc..ghi";

    List<Base64URL> parts = null;

//		try {
    parts = JOSEObject.split(s);

//		} catch (ParseException e) {
//
//			fail(e.getMessage());
//		}

    expect(3, parts.length);

    expect("abc", parts[0].toString());
    expect("", parts[1].toString());
    expect("ghi", parts[2].toString());
  });


  test('testSplitEmptyFiveParts', () {

    // JWS with empty payload
    String s = "....";

    List<Base64URL> parts = null;

//		try {
    parts = JOSEObject.split(s);

//		} catch (ParseException e) {
//
//			fail(e.getMessage());
//		}

    expect(5, parts.length);

    expect("", parts[0].toString());
    expect("", parts[1].toString());
    expect("", parts[2].toString());
    expect("", parts[3].toString());
    expect("", parts[4].toString());
  });


  test('testSplitException', () {

    // Illegal JOSE
    String s = "abc.def";

    List<Base64URL> parts = null;

//    try {
    parts = JOSEObject.split(s);

//			fail("Failed to raise exception");
//
//		} catch (ParseException e) {
//
//			// ok
//		}
  });


  test('testMIMETypes', () {

    expect("application/jose; charset=UTF-8", JOSEObject.MIME_TYPE_COMPACT);
    expect("application/jose+json; charset=UTF-8", JOSEObject.MIME_TYPE_JS);
  });
/*

*/
}
