part of jose_jwt.jwt;

/**
 * Parser for plain, signed and encrypted JSON Web Tokens (JWTs).
 *
 * @author Vladimir Dzhuvinov
 * @author Junya Hayashi
 * @version $version$ (2014-11-14)
 */
class JWTParser {

  /**
   * Parses a plain, signed or encrypted JSON Web Token (JWT) from the
   * specified string in compact format.
   *
   * @param s The string to parse. Must not be {@code null}.
   *
   * @return The corresponding {@link PlainJWT}, {@link SignedJWT} or
   *         {@link EncryptedJWT} instance.
   *
   * @throws ParseException If the string couldn't be parsed to a valid
   *                        plain, signed or encrypted JWT.
   */
  static JWT parse(final String s) {

    final int firstDotPos = s.indexOf(".");

    if (firstDotPos == -1)
      throw new ParseError("Invalid JWT serialization: Missing dot delimiter(s)", 0);

    Base64URL header = new Base64URL(s.substring(0, firstDotPos));

    JSONObject jsonObject;

    try {
      jsonObject = JSONObjectUtils.parseJSONObject(header.decodeToString());

    } catch (e) {
      // ParseException
      throw new ParseError("Invalid plain/JWS/JWE header: " + e.getMessage(), 0);
    }

    Algorithm alg = Header.parseAlgorithm(jsonObject);

    if (alg == Algorithm.NONE) {
      return PlainJWT.parse(s);
    } else if (alg is JWSAlgorithm) {
      return SignedJWT.parse(s);
    } else if (alg is JWEAlgorithm) {
      return EncryptedJWT.parse(s);
    } else {
      throw new StateError("Unexpected algorithm type: $alg");
    }
  }

  /**
   * Parses a plain, signed or encrypted JSON Web Token (JWT) from the
   * specified string in compact format.
   *
   * @param s       The string to parse. Must not be {@code null}.
   * @param handler Handler for the parsed JWT. Must not be {@code null}.
   *
   * @return The object returned by the handler, {@code null} if none is
   *         returned.
   *
   * @throws ParseException If the string couldn't be parsed to a valid
   *                        plain, signed or encrypted JWT.
   */
  //static dynamic parseWithHandler(final String s, final JWTHandler<T> handler) {
  static dynamic parseWithHandler(final String s, final JWTHandler handler) {
// <T>
    JWT jwt = parse(s);

    if (jwt is PlainJWT) {
      return handler.onPlainJWT(jwt);
    } else if (jwt is SignedJWT) {
      return handler.onSignedJWT(jwt);
    } else {
      return handler.onEncryptedJWT(jwt);
    }
  }

  /**
   * Prevents instantiation.
   */
  JWTParser._() {

  }
}
