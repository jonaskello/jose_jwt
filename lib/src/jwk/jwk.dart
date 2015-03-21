part of jose_jwt.jwk;

/**
 * The base abstract class for JSON Web Keys (JWKs). It serialises to a JSON
 * object.
 *
 * <p>The following JSON object members are common to all JWK types:
 *
 * <ul>
 *     <li>{@link #getKeyType kty} (required)
 *     <li>{@link #getKeyUse use} (optional)
 *     <li>{@link #getKeyOperations key_ops} (optional)
 *     <li>{@link #getKeyID kid} (optional)
 * </ul>
 *
 * <p>Example JWK (of the Elliptic Curve type):
 *
 * <pre>
 * {
 *   "kty" : "EC",
 *   "crv" : "P-256",
 *   "x"   : "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
 *   "y"   : "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
 *   "use" : "enc",
 *   "kid" : "1"
 * }
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @version $version$ (2014-04-02)
 */
abstract class JWK implements JSONAware {

  /**
   * The MIME type of JWK objects:
   * {@code application/jwk+json; charset=UTF-8}
   */
  static final String MIME_TYPE = "application/jwk+json; charset=UTF-8";

  /**
   * The key type, required.
   */
  final KeyType _kty;

  /**
   * The key use, optional.
   */
  final KeyUse _use;

  /**
   * The key operations, optional.
   */
  final Set<KeyOperation> _ops;

  /**
   * The intended JOSE algorithm for the key, optional.
   */
  final Algorithm _alg;

  /**
   * The key ID, optional.
   */
  final String _kid;

  /**
   * X.509 certificate URL, optional.
   */
  final Uri _x5u;

  /**
   * X.509 certificate thumbprint, optional.
   */
  final Base64URL _x5t;

  /**
   * The X.509 certificate chain, optional.
   */
  final List<Base64> _x5c;

  /**
   * Creates a new JSON Web Key (JWK).
   *
   * @param kty The key type. Must not be {@code null}.
   * @param use The key use, {@code null} if not specified or if the key
   *            is intended for signing as well as encryption.
   * @param ops The key operations, {@code null} if not specified.
   * @param alg The intended JOSE algorithm for the key, {@code null} if
   *            not specified.
   * @param kid The key ID, {@code null} if not specified.
   * @param x5u The X.509 certificate URL, {@code null} if not specified.
   * @param x5t The X.509 certificate thumbprint, {@code null} if not
   *            specified.
   * @param x5c The X.509 certificate chain, {@code null} if not
   *            specified.
   */
  JWK(final KeyType kty,
      final KeyUse use,
      final Set<KeyOperation> ops,
      final Algorithm alg,
      final String kid,
      final Uri x5u,
      final Base64URL x5t,
      final List<Base64> x5c) :
  _kty = kty,
  _use = use,
  _ops = ops,
  _alg = alg,
  _kid = kid,
  _x5u = x5u,
  _x5t = x5t,
  _x5c = x5c {

    if (kty == null) {
      throw new ArgumentError.notNull("kty");
    }

    if (use != null && ops != null) {
      throw new ArgumentError("They key use \"use\" and key options \"key_opts\" parameters cannot be set together");
    }

  }

  /**
   * Gets the type ({@code kty}) of this JWK.
   *
   * @return The key type.
   */
  KeyType getKeyType() {

    return _kty;
  }

  /**
   * Gets the use ({@code use}) of this JWK.
   *
   * @return The key use, {@code null} if not specified or if the key is
   *         intended for signing as well as encryption.
   */
  KeyUse getKeyUse() {

    return _use;
  }


  /**
   * Gets the operations ({@code key_ops}) for this JWK.
   *
   * @return The key operations, {@code null} if not specified.
   */
  Set<KeyOperation> getKeyOperations() {

    return _ops;
  }

  /**
   * Gets the intended JOSE algorithm ({@code alg}) for this JWK.
   *
   * @return The intended JOSE algorithm, {@code null} if not specified.
   */
  Algorithm getAlgorithm() {

    return _alg;
  }

  /**
   * Gets the ID ({@code kid}) of this JWK. The key ID can be used to
   * match a specific key. This can be used, for instance, to choose a
   * key within a {@link JWKSet} during key rollover. The key ID may also
   * correspond to a JWS/JWE {@code kid} header parameter value.
   *
   * @return The key ID, {@code null} if not specified.
   */
  String getKeyID() {

    return _kid;
  }

  /**
   * Gets the X.509 certificate URL ({@code x5u}) of this JWK.
   *
   * @return The X.509 certificate URL, {@code null} if not specified.
   */
  Uri getX509CertURL() {

    return _x5u;
  }

  /**
   * Gets the X.509 certificate thumbprint ({@code x5t}) of this JWK.
   *
   * @return The X.509 certificate thumbprint, {@code null} if not
   *         specified.
   */
  Base64URL getX509CertThumbprint() {

    return _x5t;
  }

  /**
   * Gets the X.509 certificate chain ({@code x5c}) of this JWK.
   *
   * @return The X.509 certificate chain as a unmodifiable list,
   *         {@code null} if not specified.
   */
  List<Base64> getX509CertChain() {

    if (_x5c == null) {
      return null;
    }

//		return Collections.unmodifiableList(x5c);
    return new UnmodifiableListView(_x5c);
  }

  /**
   * Returns {@code true} if this JWK contains private or sensitive
   * (non-public) parameters.
   *
   * @return {@code true} if this JWK contains private parameters, else
   *         {@code false}.
   */
  bool isPrivate();

  /**
   * Creates a copy of this JWK with all private or sensitive parameters
   * removed.
   *
   * @return The newly created JWK, or {@code null} if none can be
   *         created.
   */
  JWK toPublicJWK();

  /**
   * Returns a JSON object representation of this JWK. This method is
   * intended to be called from extending classes.
   *
   * <p>Example:
   *
   * <pre>
   * {
   *   "kty" : "RSA",
   *   "use" : "sig",
   *   "kid" : "fd28e025-8d24-48bc-a51a-e2ffc8bc274b"
   * }
   * </pre>
   *
   * @return The JSON object representation.
   */
  Map toJson() {

//    JSONObject o = new JSONObject();
    Map o = new Map();

    o["kty"] = _kty.getValue();

    if (_use != null) {
//      o.put("use", _use.identifier());
      o["use"] = _use.toString();
    }

    if (_ops != null) {

      List<String> sl = new List(_ops.length);

      for (KeyOperation op in _ops) {
        sl.add(op.identifier());
      }

      o["key_ops"] = sl;
    }

    if (_alg != null) {
      o["alg"] = _alg.getName();
    }

    if (_kid != null) {
      o["kid"] = _kid;
    }

    if (_x5u != null) {
      o["x5u"] = _x5u.toString();
    }

    if (_x5t != null) {
      o["x5t"] = _x5t.toString();
    }

    if (_x5c != null) {
      o["x5c"] = _x5c;
    }

    return o;
  }

  /**
   * Returns the JSON object string representation of this JWK.
   *
   * @return The JSON object string representation.
   */
  @override
  String toJsonString() {

    return toJson().toString();
  }

  /**
   * @see #toJSONString
   */
  @override
  String toString() {

    return toJson().toString();
  }

  /**
   * Parses a JWK from the specified JSON object string representation.
   * The JWK must be an {@link ECKey}, an {@link RSAKey}, or a
   * {@link OctetSequenceKey}.
   *
   * @param s The JSON object string to parse. Must not be {@code null}.
   *
   * @return The JWK.
   *
   * @throws ParseException If the string couldn't be parsed to a
   *                        supported JWK.
   */
  static JWK fromJsonString(final String s) {

    return fromJson(JSON.decode(s));
  }

  /**
   * Parses a JWK from the specified JSON object representation. The JWK
   * must be an {@link ECKey}, an {@link RSAKey}, or a
   * {@link OctetSequenceKey}.
   *
   * @param jsonObject The JSON object to parse. Must not be
   *                   {@code null}.
   *
   * @return The JWK.
   *
   * @throws ParseException If the JSON object couldn't be parsed to a
   *                        supported JWK.
   */
  static JWK fromJson(final Map jsonObject) {

    KeyType kty = KeyType.parse(JSONUtils.getString(jsonObject, "kty"));

    if (kty == KeyType.EC) {

      return ECKey.fromJson(jsonObject);

    } else if (kty == KeyType.RSA) {

      return RSAKey.fromJson(jsonObject);

    } else if (kty == KeyType.OCT) {

      return OctetSequenceKey.fromJson(jsonObject);

    } else {

      throw new ParseError("Unsupported key type \"kty\" parameter: $kty", 0);
    }
  }

}
