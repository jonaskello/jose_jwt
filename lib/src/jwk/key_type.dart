part of jose_jwt.jwk;

/**
 * Key type. Represents the {@code kty} parameter in a JSON Web Key (JWK).
 * This class is immutable.
 *
 * <p>Includes constants for the following standard key types:
 *
 * <ul>
 *     <li>{@link #EC}
 *     <li>{@link #RSA}
 *     <li>{@link #OCT}
 * </ul>
 *
 * <p>Additional key types can be defined using the constructor.
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @version $version$ (2013-05-29)
 */
//@Immutable
class KeyType implements JSONAware {

  /**
   * The key type value.
   */
  final String _value;


  /**
   * The implementation requirement, {@code null} if not known.
   */
  final Requirement _requirement;


  /**
   * Elliptic Curve (DSS) key type (recommended).
   */
  static final KeyType EC = new KeyType("EC", Requirement.RECOMMENDED);


  /**
   * RSA (RFC 3447) key type (required).
   */
  static final KeyType RSA = new KeyType("RSA", Requirement.REQUIRED);


  /**
   * Octet sequence key type (optional)
   */
  static final KeyType OCT = new KeyType("oct", Requirement.OPTIONAL);

  /**
   * Creates a new key type with the specified value and implementation
   * requirement.
   *
   * @param value The key type value. Values are case sensitive. Must not
   *              be {@code null}.
   * @param req   The implementation requirement, {@code null} if not
   *              known.
   */
  KeyType(this._value, this._requirement) {

    if (_value == null) {
      throw new ArgumentError.notNull("value");
    }

  }

  /**
   * Gets the value of this key type. Values are case sensitive.
   *
   * @return The key type.
   */
  String getValue() {

    return _value;
  }

  /**
   * Gets the implementation requirement of this key type.
   *
   * @return The implementation requirement, {@code null} if not known.
   */
  Requirement getRequirement() {

    return _requirement;
  }

  /**
   * Overrides {@code Object.hashCode()}.
   *
   * @return The object hash code.
   */
  @override
  int get hashCode => _value.hashCode;

  /**
   * Overrides {@code Object.equals()}.
   *
   * @param object The object to compare to.
   *
   * @return {@code true} if the objects have the same value, otherwise
   *         {@code false}.
   */
  @override
  bool operator ==(final Object object) =>
  object is KeyType &&
  this.toString() == object.toString();

  /**
   * Returns the string representation of this key type.
   *
   * @see #getValue
   *
   * @return The string representation.
   */
  @override
  String toString() => _value;

  /**
   * Returns the JSON string representation of this key type.
   *
   * @return The JSON string representation.
   */
  @override
  String toJSONString() {

    StringBuffer sb = new StringBuffer();
    sb.write('"');
    sb.write(JSONObject.escape(_value));
    sb.write('"');
    return sb.toString();
  }

  /**
   * Parses a key type from the specified {@code kty} parameter value.
   *
   * @param s The string to parse. Must not be {@code null}.
   *
   * @return The key type (matching standard key type constant, else a
   *         newly created one).
   */
  static KeyType parse(final String s) {

    if (s == EC.getValue()) {

      return EC;

    } else if (s == RSA.getValue()) {

      return RSA;

    } else if (s == OCT.getValue()) {

      return OCT;

    } else {

      return new KeyType(s, null);
    }
  }
}
