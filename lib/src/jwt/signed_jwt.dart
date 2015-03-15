part of jose_jwt.jwt;

/**
 * Signed JSON Web Token (JWT).
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-15)
 */
class SignedJWT extends JWSObject implements JWT {


  /**
   * Creates a new to-be-signed JSON Web Token (JWT) with the specified
   * header and claims set. The initial state will be
   * {@link com.nimbusds.jose.JWSObject.State#UNSIGNED unsigned}.
   *
   * @param header    The JWS header. Must not be {@code null}.
   * @param claimsSet The JWT claims set. Must not be {@code null}.
   */
  SignedJWT(final JWSHeader header, final ReadOnlyJWTClaimsSet claimsSet) :super(header, new Payload(claimsSet.toJSONObject()));

  /**
   * Creates a new signed JSON Web Token (JWT) with the specified
   * serialised parts. The state will be
   * {@link com.nimbusds.jose.JWSObject.State#SIGNED signed}.
   *
   * @param firstPart  The first part, corresponding to the JWS header.
   *                   Must not be {@code null}.
   * @param secondPart The second part, corresponding to the claims set
   *                   (payload). Must not be {@code null}.
   * @param thirdPart  The third part, corresponding to the signature.
   *                   Must not be {@code null}.
   *
   * @throws ParseException If parsing of the serialised parts failed.
   */
  SignedJWT.fromParts(final Base64URL firstPart, final Base64URL secondPart, final Base64URL thirdPart) : super(firstPart, secondPart, thirdPart);

  @override
  ReadOnlyJWTClaimsSet getJWTClaimsSet() {

    JSONObject json = getPayload().toJSONObject();

    if (json == null) {
      throw new ParseError("Payload of JWS object is not a valid JSON object", 0);
    }

    return JWTClaimsSet.parse(json);
  }

  /**
   * Parses a signed JSON Web Token (JWT) from the specified string in
   * compact format.
   *
   * @param s The string to parse. Must not be {@code null}.
   *
   * @return The signed JWT.
   *
   * @throws ParseException If the string couldn't be parsed to a valid
   *                        signed JWT.
   */
  static SignedJWT parse(final String s) {

    List<Base64URL> parts = JOSEObject.split(s);

    if (parts.length != 3) {
      throw new ParseError("Unexpected number of Base64URL parts, must be three", 0);
    }

    return new SignedJWT(parts[0], parts[1], parts[2]);
  }

}

