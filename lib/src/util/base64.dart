part of jose_jwt.util;

/**
 * Base64-encoded object.
 *
 * @author Vladimir Dzhuvinov
 */
//@immutable
class Base64 implements JSONAware {

/*
	/**
	 * UTF-8 is the required character set for all JOSE + JWT objects.
	 */
	static final Charset CHARSET = Charset.forName("UTF-8");
*/

  /**
   * The Base64 value.
   */
  final String _value;


  /**
   * Creates a new Base64-encoded object.
   *
   * @param base64 The Base64-encoded object value. The value is not
   *               validated for having characters from a Base64
   *               alphabet. Must not be {@code null}.
   */
  Base64(final String base64) : _value = base64 {

    if (base64 == null) {

      throw new ArgumentError("The Base64 value must not be null");
    }

  }

  /**
   * Decodes this Base64 object to a byte array.
   *
   * @return The resulting byte array.
   */
  Uint8List decode() {

    return Base64Codec.decode(value);
  }


  /**
   * Decodes this Base64 object to an unsigned big integer.
   *
   * <p>Same as {@code new BigInteger(1, base64.decode())}.
   *
   * @return The resulting big integer.
   */
  BigInteger decodeToBigInteger() {

    return new BigInteger(1, decode());
  }

  /**
   * Decodes this Base64 object to a string.
   *
   * @return The resulting string, in the UTF-8 character set.
   */
  String decodeToString() {

    return new String(decode(), CHARSET);
  }

  /**
   * Returns a JSON string representation of this object.
   *
   * @return The JSON string representation of this object.
   */
  @override
  String toJSONString() {

    return "\"" + JSONValue.escape(_value) + "\"";
  }


  /**
   * Returns a Base64 string representation of this object. The string
   * will be chunked into 76 character blocks separated by CRLF.
   *
   * @return The Base64 string representation, chunked into 76 character
   *         blocks separated by CRLF.
   */
  @override
  String toString() => _value;

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
  object is Base64 &&
  this.toString() == object.toString();

  /**
   * Base64-encodes the specified byte array.
   *
   * @param bytes The byte array to encode. Must not be {@code null}.
   *
   * @return The resulting Base64 object.
   */
  static Base64 encodeBytes(final Uint8List bytes) {

    return new Base64(Base64Codec.encodeToString(bytes, false));
  }

  /**
   * Base64-encodes the specified big integer, without the sign bit.
   *
   * @param bigInt The big integer to encode. Must not be {@code null}.
   *
   * @return The resulting Base64 object.
   */
  static Base64 encodeBigInteger(final BigInteger bigInt) {

    return encodeBytes(BigIntegerUtils.toBytesUnsigned(bigInt));
  }

  /**
   * Base64-encodes the specified string.
   *
   * @param text The string to encode. Must be in the UTF-8 character set
   *             and not {@code null}.
   *
   * @return The resulting Base64 object.
   */
  static Base64 encodeString(final String text) {

    return encodeBytes(text.getBytes(CHARSET));
  }

}
