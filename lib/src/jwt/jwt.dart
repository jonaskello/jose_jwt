part of jose_jwt.jwt;

/**
 * JSON Web Token (JWT) interface.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-07-08)
 */
abstract class JWT {

  /**
   * Gets the JOSE header of the JSON Web Token (JWT).
   *
   * @return The header.
   */
  Header getHeader();

  /**
   * Gets the claims set of the JSON Web Token (JWT).
   *
   * @return The claims set, {@code null} if not available (for an
   *         encrypted JWT that isn't decrypted).
   *
   * @throws ParseException If the payload of the JWT doesn't represent a
   *                        valid JSON object and a JWT claims set.
   */
  ReadOnlyJWTClaimsSet getJWTClaimsSet();


  /**
   * Gets the original parsed Base64URL parts used to create the JSON Web
   * Token (JWT).
   *
   * @return The original Base64URL parts used to creates the JWT,
   *         {@code null} if the JWT was created from scratch. The
   *         individual parts may be empty or {@code null} to indicate a
   *         missing part.
   */
  List<Base64URL> getParsedParts();


  /**
   * Gets the original parsed string used to create the JSON Web Token
   * (JWT).
   *
   * @see #getParsedParts
   *
   * @return The parsed string used to create the JWT, {@code null} if
   *         the JWT was created from scratch.
   */
  String getParsedString();


  /**
   * Serialises the JSON Web Token (JWT) to its compact format consisting
   * of Base64URL-encoded parts delimited by period ('.') characters.
   *
   * @return The serialised JWT.
   *
   * @throws IllegalStateException If the JWT is not in a state that
   *                               permits serialisation.
   */
  String serialize();
}