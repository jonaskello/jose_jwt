library jose_jwt.test.jose.plain_object_test;

import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jose.dart';

/**
 * Tests plaintext JOSE object parsing and serialisation.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-07-08)
 */
//public class PlainObjectTest extends TestCase {
main() {

  test('testSerializeAndParse', () {

    Payload payload = new Payload.fromString("Hello world!");

    PlainObject p = new PlainObject.payloadOnly(payload);

    expect(p.getHeader(), isNotNull);
    expect("Hello world!", p.getPayload().toString());

    PlainHeader h = p.getHeader();
    expect(Algorithm.NONE, h.getAlgorithm());
    expect(h.getType(), isNull);
    expect(h.getContentType(), isNull);
    expect(h.getCustomParams().isEmpty,isTrue);

    String serializedJOSEObject = p.serialize();

    p = PlainObject.parse(serializedJOSEObject);

    h = p.getHeader();
    expect(Algorithm.NONE, h.getAlgorithm());
    expect(h.getType(), isNull);
    expect(h.getContentType(), isNull);
    expect(h.getCustomParams().isEmpty, isTrue);

    expect("Hello world!", p.getPayload().toString());

    expect(serializedJOSEObject, p.getParsedString());
  });

}

