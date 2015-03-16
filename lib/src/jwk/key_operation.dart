part of jose_jwt.jwk;

/**
 * Enumeration of key operations. Represents the {@code key_ops} parameter in a
 * JSON Web Key (JWK).
 *
 * <p>JWK operation values:
 *
 * <ul>
 *     <li>{@link #SIGN sign}
 *     <li>{@link #VERIFY verify}
 *     <li>{@link #ENCRYPT encrypt}
 *     <li>{@link #DECRYPT decrypt}
 *     <li>{@link #WRAP_KEY wrapKey}
 *     <li>{@link #UNWRAP_KEY unwrapKey}
 *     <li>{@link #DERIVE_KEY deriveKey}
 *     <li>{@link #DERIVE_BITS deriveBits}
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-04-02)
 */
//enum KeyOperation {
class KeyOperation {

  /**
   * Compute signature or MAC.
   */
  static const String SIGN = "sign";

  /**
   * Verify signature or MAC.
   */
  static const String VERIFY = "verify";

  /**
   * Encrypt content.
   */
  static const String ENCRYPT = "encrypt";

  /**
   * Decrypt content and validate decryption, if applicable.
   */
  static const String DECRYPT = "decrypt";

  /**
   * Encrypt key.
   */
  static const String WRAP_KEY = "wrapKey";


  /**
   * Decrypt key and validate decryption, if applicable.
   */
  static const String UNWRAP_KEY = "unwrapKey";


  /**
   * Derive key.
   */
  static const String DERIVE_KEY = "deriveKey";

  /**
   * Derive bits not to be used as a key.
   */
  static const String DERIVE_BITS = "deriveBits";

  static const List<String> values = const [
      SIGN,
      VERIFY,
      ENCRYPT,
      DECRYPT,
      WRAP_KEY,
      UNWRAP_KEY,
      DERIVE_KEY,
      DERIVE_BITS
  ];

  /**
   * The key operation identifier.
   */
  final String _identifier;

  /**
   * Creates a new key operation with the specified identifier.
   *
   * @param identifier The key operation identifier. Must not be
   *                   {@code null}.
   */
  KeyOperation._(this._identifier) {

    if (_identifier == null)
      throw new ArgumentError.notNull("identifier");
  }

  /**
   * Returns the identifier of this key use.
   *
   * @return The identifier.
   */
  String identifier() {

    return _identifier;
  }

  /**
   * @see #identifier()
   */
  @override
  String toString() => identifier();

  /**
   * Parses a key operation set from the specified JWK {@code key_ops}
   * parameter value.
   *
   * @param sl The string list to parse. May be {@code null}.
   *
   * @return The key operation set, {@code null} if none.
   *
   * @throws ParseException If the string list couldn't be parsed to a
   *                        valid key operation list.
   */
  static Set<KeyOperation> parse(final List<String> sl) {

    if (sl == null) {
      return null;
    }

    Set<KeyOperation> keyOps = new Set();

    for (String s in sl) {

      if (s == null) {
        // skip
        continue;
      }

      KeyOperation parsedOp = null;

      for (KeyOperation op in KeyOperation.values) {

        if (s == op.identifier()) {
          parsedOp = op;
          break;
        }
      }

      if (parsedOp != null) {
        keyOps.add(parsedOp);
      }
      else {
        throw new ParseError("Invalid JWK operation: " + s, 0);
      }
    }

    return keyOps;
  }

}
