library jose_jwt.test.jose.algorithm_test;

import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jose.dart';

/**
 * Tests the base Algorithm class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-26)
 */
//public class AlgorithmTest extends TestCase {
main() {

  test('testNoneConstant', () {

    expect("none", Algorithm.NONE.getName());
    expect(Requirement.REQUIRED, Algorithm.NONE.getRequirement());

    expect(Algorithm.NONE, new Algorithm("none", Requirement.REQUIRED));
  });


  test('testMinimalConstructor', () {

    Algorithm alg = new Algorithm.withName("my-alg");

    expect("my-alg", alg.getName());
    expect("my-alg", alg.toString());

    expect(alg.getRequirement(), isNull);
  });


  test('testFullContructor', () {

    Algorithm alg = new Algorithm("my-alg", Requirement.OPTIONAL);

    expect("my-alg", alg.getName());
    expect("my-alg", alg.toString());

    expect(Requirement.OPTIONAL, alg.getRequirement());
  });


  test('testEquality', () {

    Algorithm alg1 = new Algorithm.withName("my-alg");
    Algorithm alg2 = new Algorithm.withName("my-alg");

    expect(alg1 == alg2, isTrue);
  });


  test('testEqualityDifferentRequirementLevels', () {

    Algorithm alg1 = new Algorithm("my-alg", Requirement.REQUIRED);
    Algorithm alg2 = new Algorithm("my-alg", Requirement.OPTIONAL);

    expect(alg1 == alg2, isTrue);
  });


  test('testInequality', () {

    Algorithm alg1 = new Algorithm.withName("my-alg");
    Algorithm alg2 = new Algorithm.withName("your-alg");

    expect(alg1 == alg2, isFalse);
  });


  test('testHashCode', () {

    Algorithm alg1 = new Algorithm.withName("my-alg");
    Algorithm alg2 = new Algorithm.withName("my-alg");

    expect(alg1.hashCode, alg2.hashCode);
  });

}
