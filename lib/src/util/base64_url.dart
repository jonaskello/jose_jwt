part of jose_jwt.util;

/**
 * Base64URL-encoded object.
 *
 * <p>Related specifications:
 *
 * <ul>
 *     <li>RFC 4648.
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-05-16)
 */
//@Immutable
class Base64URL extends Base64 {


  /**
   * Creates a new Base64URL-encoded object.
   *
   * @param base64URL The Base64URL-encoded object value. The value is
   *                  not validated for having characters from the
   *                  Base64URL alphabet. Must not be {@code null}.
   */
  Base64URL(final String base64URL) :super(base64URL);

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
  object is Base64URL &&
  this.toString() == object.toString();

  /**
   * Base64URL-encodes the specified byte array.
   *
   * @param bytes The byte array to encode. Must not be {@code null}.
   *
   * @return The resulting Base64URL object.
   */
  static Base64URL encodeBytes(final Uint8List bytes) {

    return new Base64URL(Base64Codec.encodeToString(bytes, true));
  }

  /**
   * Base64URL-encodes the specified big integer, without the sign bit.
   *
   * @param bigInt The big integer to encode. Must not be {@code null}.
   *
   * @return The resulting Base64URL object.
   */
  static Base64URL encodeBigInteger(final BigInteger bigInt) {

    return encodeBytes(BigIntegerUtils.toBytesUnsigned(bigInt));
  }

  /**
   * Base64URL-encodes the specified string.
   *
   * @param text The string to encode. Must be in the UTF-8 character set
   *             and not {@code null}.
   *
   * @return The resulting Base64URL object.
   */
  static Base64URL encodeString(final String text) {

    return encodeBytes(text.getBytes(Base64.CHARSET));
  }

}

