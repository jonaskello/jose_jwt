part of jose_jwt.jose;

/**
 * The base abstract class for plaintext (unsecured), JSON Web Signature (JWS)
 * and JSON Web Encryption (JWE) objects.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-11-18)
 */
abstract class JOSEObject {

  /**
   * The MIME type of JOSE objects serialised to a compact form:
   * {@code application/jose; charset=UTF-8}
   */
  static final String MIME_TYPE_COMPACT = "application/jose; charset=UTF-8";


  /**
   * The MIME type of JOSE objects serialised to a JSON object form:
   * {@code application/jose+json; charset=UTF-8}
   */
  static final String MIME_TYPE_JS = "application/jose+json; charset=UTF-8";


  /**
   * The payload (message), {@code null} if not defined.
   */
  Payload _payload;


  /**
   * The original parsed Base64URL parts, {@code null} if the JOSE object
   * was created from scratch. The individual parts may be empty or
   * {@code null} to indicate a missing part.
   */
  List<Base64URL> _parsedParts;

  /**
   * Creates a new JOSE object. The payload and the original parsed
   * Base64URL parts are not defined.
   */
  JOSEObject() {

    _payload = null;

    _parsedParts = null;
  }


  /**
   * Creates a new JOSE object with the specified payload.
   *
   * @param payload The payload, {@code null} if not available (e.g for
   *                an encrypted JWE object).
   */
  JOSEObject.withPayload(final Payload payload) {

    _payload = payload;
  }

  /**
   * Returns the header of this JOSE object.
   *
   * @return The header.
   */
  Header getHeader();


  /**
   * Sets the payload of this JOSE object.
   *
   * @param payload The payload, {@code null} if not available (e.g. for
   *                an encrypted JWE object).
   */
  void setPayload(final Payload payload) {

    _payload = payload;
  }

  /**
   * Returns the payload of this JOSE object.
   *
   * @return The payload, {@code null} if not available (for an encrypted
   *         JWE object that hasn't been decrypted).
   */
  Payload getPayload() {
    return _payload;
  }

  /**
   * Sets the original parsed Base64URL parts used to create this JOSE
   * object.
   *
   * @param parts The original Base64URL parts used to creates this JOSE
   *              object, {@code null} if the object was created from
   *              scratch. The individual parts may be empty or
   *              {@code null} to indicate a missing part.
   */
  void setParsedParts(final List<Base64URL> parts) {
    _parsedParts = parts;
  }

  /**
   * Returns the original parsed Base64URL parts used to create this JOSE
   * object.
   *
   * @return The original Base64URL parts used to creates this JOSE
   *         object, {@code null} if the object was created from scratch.
   *         The individual parts may be empty or {@code null} to
   *         indicate a missing part.
   */
  List<Base64URL> getParsedParts() {

    return _parsedParts;
  }

  /**
   * Returns the original parsed string used to create this JOSE object.
   *
   * @see #getParsedParts
   *
   * @return The parsed string used to create this JOSE object,
   *         {@code null} if the object was creates from scratch.
   */
  String getParsedString() {

    if (_parsedParts == null) {
      return null;
    }

    StringBuffer sb = new StringBuffer();

    for (Base64URL part in _parsedParts) {

      if (sb.length > 0) {
        sb.write('.');
      }

      if (part != null) {
        sb.write(part.toString());
      }
    }

    return sb.toString();
  }

  /**
   * Serialises this JOSE object to its compact format consisting of
   * Base64URL-encoded parts delimited by period ('.') characters.
   *
   * @return The serialised JOSE object.
   *
   * @throws IllegalStateException If the JOSE object is not in a state
   *                               that permits serialisation.
   */
  String serialize();

  /**
   * Splits a serialised JOSE object into its Base64URL-encoded parts.
   *
   * @param s The serialised JOSE object to split. Must not be
   *          {@code null}.
   *
   * @return The JOSE Base64URL-encoded parts (three for plaintext and
   *         JWS objects, five for JWE objects).
   *
   * @throws ParseException If the specified string couldn't be split
   *                        into three or five Base64URL-encoded parts.
   */
  static List<Base64URL> split(final String s) {

    // We must have 2 (JWS) or 4 dots (JWE)

    // String.split() cannot handle empty parts
    final int dot1 = s.indexOf(".");

    if (dot1 == -1) {
      throw new ParseError("Invalid serialized plain/JWS/JWE object: Missing part delimiters", 0);
    }

    final int dot2 = s.indexOf(".", dot1 + 1);

    if (dot2 == -1) {
      throw new ParseError("Invalid serialized plain/JWS/JWE object: Missing second delimiter", 0);
    }

    // Third dot for JWE only
    final int dot3 = s.indexOf(".", dot2 + 1);

    if (dot3 == -1) {

      // Two dots only? -> We have a JWS
      List<Base64URL> parts = new List<Base64URL>(3);
      parts[0] = new Base64URL(s.substring(0, dot1));
      parts[1] = new Base64URL(s.substring(dot1 + 1, dot2));
      parts[2] = new Base64URL(s.substring(dot2 + 1));
      return parts;
    }

    // Fourth final dot for JWE
    final int dot4 = s.indexOf(".", dot3 + 1);

    if (dot4 == -1) {
      throw new ParseError("Invalid serialized JWE object: Missing fourth delimiter", 0);
    }

    if (dot4 != -1 && s.indexOf(".", dot4 + 1) != -1) {
      throw new ParseError("Invalid serialized plain/JWS/JWE object: Too many part delimiters", 0);
    }

    // Four dots -> five parts
    List<Base64URL> parts = new List<Base64URL>(5);
    parts[0] = new Base64URL(s.substring(0, dot1));
    parts[1] = new Base64URL(s.substring(dot1 + 1, dot2));
    parts[2] = new Base64URL(s.substring(dot2 + 1, dot3));
    parts[3] = new Base64URL(s.substring(dot3 + 1, dot4));
    parts[4] = new Base64URL(s.substring(dot4 + 1));
    return parts;
  }

  /**
   * Parses a JOSE object from the specified string in compact format.
   *
   * @param s The string to parse. Must not be {@code null}.
   *
   * @return The corresponding {@link PlainObject}, {@link JWSObject} or
   *         {@link JWEObject} instance.
   *
   * @throws ParseException If the string couldn't be parsed to a valid
   *                       plaintext, JWS or JWE object.
   */
  static JOSEObject parseString(final String s) {

    List<Base64URL> parts = split(s);

    Map jsonObject;

    try {
      jsonObject = JSON.decode(parts[0].decodeToString());

    } catch (e) {
      if (e is ParseError)
        throw new ParseError("Invalid plain/JWS/JWE header: $e", 0);
    }

    Algorithm alg = Header.parseAlgorithm(jsonObject);

    if (alg == Algorithm.NONE) {
      return PlainObject.parse(s);
    } else if (alg is JWSAlgorithm) {
      return JWSObject.parse(s);
    } else if (alg is JWEAlgorithm) {
      return JWEObject.parse(s);
    } else {
      throw new StateError("Unexpected algorithm type: $alg");
    }
  }

	/**
	 * Parses a {@link PlainObject plain}, {@link JWSObject JWS} or
	 * {@link JWEObject JWE object} from the specified string in compact
	 * format.
	 *
	 * @param s       The string to parse. Must not be {@code null}.
	 * @param handler Handler for the parsed JOSE object. Must not be
	 *                {@code null}.
	 *
	 * @return The object returned by the handler, {@code null} if none is
	 *         returned.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid
	 *                        plain, signed or encrypted JWT.
	 */
//  static <T> T parse(final String s, JOSEObjectHandler<T> handler)
  static dynamic parseWithHandler(final String s, JOSEObjectHandler handler) {

		JOSEObject joseObject = parseString(s);

		if (joseObject is PlainObject) {
			return handler.onPlainObject(joseObject);
		} else if (joseObject is JWSObject) {
			return handler.onJWSObject(joseObject);
		} else {
			return handler.onJWEObject(joseObject);
		}
	}

}
