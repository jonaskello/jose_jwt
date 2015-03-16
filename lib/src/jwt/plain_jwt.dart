part of jose_jwt.jwt;

/**
 * Plain JSON Web Token (JWT).
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-08-21)
 */
class PlainJWT extends PlainObject implements JWT {


  /**
   * Creates a new plain JSON Web Token (JWT) with a default
   * {@link com.nimbusds.jose.PlainHeader} and the specified claims
   * set.
   *
   * @param claimsSet The JWT claims set. Must not be {@code null}.
   */
  PlainJWT(final ReadOnlyJWTClaimsSet claimsSet) : super.payloadOnly(new Payload.fromJson(claimsSet.toJson()));

  /**
   * Creates a new plain JSON Web Token (JWT) with the specified header
   * and claims set.
   *
   * @param header    The plain header. Must not be {@code null}.
   * @param claimsSet The JWT claims set. Must not be {@code null}.
   */
  PlainJWT.fromHeaderAndClaimSet(final PlainHeader header, final ReadOnlyJWTClaimsSet claimsSet)
  : super(header, new Payload.fromJson(claimsSet.toJson()));

  /**
   * Creates a new plain JSON Web Token (JWT) with the specified
   * Base64URL-encoded parts.
   *
   * @param firstPart  The first part, corresponding to the plain header.
   *                   Must not be {@code null}.
   * @param secondPart The second part, corresponding to the claims set
   *                   (payload). Must not be {@code null}.
   *
   * @throws ParseException If parsing of the serialised parts failed.
   */
  PlainJWT.fromParts(final Base64URL firstPart, final Base64URL secondPart)
  : super.fromParts(firstPart, secondPart);

  @override
  ReadOnlyJWTClaimsSet getJWTClaimsSet() {

    Map json = getPayload().toJson();

    if (json == null) {

      throw new ParseError("Payload of plain JOSE object is not a valid JSON object", 0);
    }

    return JWTClaimsSet.fromJson(json);
  }

  /**
   * Parses a plain JSON Web Token (JWT) from the specified string in
   * compact format.
   *
   * @param s The string to parse. Must not be {@code null}.
   *
   * @return The plain JWT.
   *
   * @throws ParseException If the string couldn't be parsed to a valid
   *                        plain JWT.
   */
  static PlainJWT parse(final String s) {

    List<Base64URL> parts = JOSEObject.split(s);

    if (!parts[2].toString().isEmpty) {

      throw new ParseError("Unexpected third Base64URL part in the plain JWT object", 0);
    }

    return new PlainJWT.fromParts(parts[0], parts[1]);
  }

}

