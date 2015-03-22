part of jose_jwt.jwk;

/**
 * Enumeration of public key uses. Represents the {@code use} parameter in a
 * JSON Web Key (JWK).
 *
 * <p>Public JWK use values:
 *
 * <ul>
 *     <li>{@link #SIGNATURE sig}
 *     <li>{@link #ENCRYPTION enc}
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-04-02)
 */
//public enum KeyUse {
enum KeyUse {

/**
 * Signature.
 */
//	SIGNATURE("sig"),
//  static const String SIGNATURE = "sig";
SIGNATURE,

/**
 * Encryption.
 */
//	ENCRYPTION("enc");
//  static const String ENCRYPTION = "enc";
ENCRYPTION

/*

  static const values = const [SIGNATURE, ENCRYPTION];

  /**
   * The public key use identifier.
   */
  final String _identifier;

  /**
   * Creates a new public key use with the specified identifier.
   *
   * @param identifier The public key use identifier. Must not be
   *                   {@code null}.
   */
  KeyUse._(this._identifier) {

    if (_identifier == null)
      throw new ArgumentError.notNull("identifier");

  }

  /**
   * Returns the identifier of this public key use.
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
  String toString() {

    return identifier();
  }


*/
}

class KeyUseParser {


  static String getIdentifier(KeyUse use) {

    switch (use) {
      case KeyUse.SIGNATURE :
        return "sig";
      case KeyUse.ENCRYPTION :
        return "enc";
    }

  }

  /**
   * Parses a public key use from the specified JWK {@code use} parameter
   * value.
   *
   * @param s The string to parse. May be {@code null}.
   *
   * @return The public key use, {@code null} if none.
   *
   * @throws ParseException If the string couldn't be parsed to a valid
   *                        public key use.
   */
  static KeyUse parse(final String s) {

    if (s == null) {
      return null;
    }

    for (KeyUse use in KeyUse.values) {

      if (s == getIdentifier(use)) {
        return use;
      }
    }

    throw new ParseError("Invalid JWK use: " + s, 0);
  }

}