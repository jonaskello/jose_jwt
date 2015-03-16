part of jose_jwt.jwk;

/**
 * Builder for constructing octet sequence JWKs.
 *
 * <p>Example use:
 *
 * <pre>
 * OctetSequenceKey key = new OctetSequenceKey.Builder(k).
 *                        algorithm(JWSAlgorithm.HS512).
 *                        keyID("123").
 *                        build();
 * </pre>
 */
class OctetSequenceKeyBuilder {

  /**
   * The symmetric key value.
   */
  final Base64URL _k;

  /**
   * The key use, optional.
   */
  KeyUse _use;

  /**
   * The key operations, optional.
   */
  Set<KeyOperation> _ops;

  /**
   * The intended JOSE algorithm for the key, optional.
   */
  Algorithm _alg;

  /**
   * The key ID, optional.
   */
  String _kid;

  /**
   * X.509 certificate URL, optional.
   */
  Uri _x5u;

  /**
   * X.509 certificate thumbprint, optional.
   */
  Base64URL _x5t;

  /**
   * The X.509 certificate chain, optional.
   */
  List<Base64> _x5c;

  /**
   * Creates a new octet sequence JWK builder.
   *
   * @param k The key value. It is represented as the Base64URL
   *          encoding of value's big endian representation. Must
   *          not be {@code null}.
   */
  OctetSequenceKeyBuilder(this._k) {

    if (_k == null) {
      throw new ArgumentError.notNull("k");
    }

  }

  /**
   * Creates a new octet sequence JWK builder.
   *
   * @param key The key value. Must not be empty byte array or
   *            {@code null}.
   */
  factory OctetSequenceKeyBuilder.fromBytes(final Uint8List key) {

    if (key == null || key.length == 0) {
      throw new ArgumentError.notNull("key");
    }

//    _k = Base64URL.encodeBytes(key);
    return new OctetSequenceKeyBuilder(Base64URL.encodeBytes(key));
  }

  /**
   * Sets the use ({@code use}) of the JWK.
   *
   * @param use The key use, {@code null} if not specified or if
   *            the key is intended for signing as well as
   *            encryption.
   *
   * @return This builder.
   */
  OctetSequenceKeyBuilder keyUse(final KeyUse use) {

    _use = use;
    return this;
  }

  /**
   * Sets the operations ({@code key_ops}) of the JWK (for a
   * non-key).
   *
   * @param ops The key operations, {@code null} if not
   *            specified.
   *
   * @return This builder.
   */
  OctetSequenceKeyBuilder keyOperations(final Set<KeyOperation> ops) {

    _ops = ops;
    return this;
  }


  /**
   * Sets the intended JOSE algorithm ({@code alg}) for the JWK.
   *
   * @param alg The intended JOSE algorithm, {@code null} if not
   *            specified.
   *
   * @return This builder.
   */
  OctetSequenceKeyBuilder algorithm(final Algorithm alg) {

    _alg = alg;
    return this;
  }

  /**
   * Sets the ID ({@code kid}) of the JWK. The key ID can be used
   * to match a specific key. This can be used, for instance, to
   * choose a key within a {@link JWKSet} during key rollover.
   * The key ID may also correspond to a JWS/JWE {@code kid}
   * header parameter value.
   *
   * @param kid The key ID, {@code null} if not specified.
   *
   * @return This builder.
   */
  OctetSequenceKeyBuilder keyID(final String kid) {

    _kid = kid;
    return this;
  }


  /**
   * Sets the X.509 certificate URL ({@code x5u}) of the JWK.
   *
   * @param x5u The X.509 certificate URL, {@code null} if not
   *            specified.
   *
   * @return This builder.
   */
  OctetSequenceKeyBuilder x509CertURL(final Uri x5u) {

    _x5u = x5u;
    return this;
  }


  /**
   * Sets the X.509 certificate thumbprint ({@code x5t}) of the
   * JWK.
   *
   * @param x5t The X.509 certificate thumbprint, {@code null} if
   *            not specified.
   *
   * @return This builder.
   */
  OctetSequenceKeyBuilder x509CertThumbprint(final Base64URL x5t) {

    _x5t = x5t;
    return this;
  }

  /**
   * Sets the X.509 certificate chain ({@code x5c}) of the JWK.
   *
   * @param x5c The X.509 certificate chain as a unmodifiable
   *            list, {@code null} if not specified.
   *
   * @return This builder.
   */
  OctetSequenceKeyBuilder x509CertChain(final List<Base64> x5c) {

    _x5c = x5c;
    return this;
  }

  /**
   * Builds a new octet sequence JWK.
   *
   * @return The octet sequence JWK.
   *
   * @throws IllegalStateException If the JWK parameters were
   *                               inconsistently specified.
   */
  OctetSequenceKey build() {

    try {
      return new OctetSequenceKey(_k, _use, _ops, _alg, _kid, _x5u, _x5t, _x5c);

    } catch (e) {
      if (e is ArgumentError)
//        throw new StateError(e.toString(), e);
        throw new StateError(e.toString());
    }
  }

}


/**
 * {@link KeyType#OCT Octet sequence} JSON Web Key (JWK), used to represent
 * symmetric keys. This class is immutable.
 *
 * <p>Example JSON object representation of an octet sequence JWK:
 *
 * <pre>
 * {
 *   "kty" : "oct",
 *   "alg" : "A128KW",
 *   "k"   : "GawgguFyGrWKav7AX4VKUg"
 * }
 * </pre>
 *
 * @author Justin Richer
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-01-20)
 */
//@Immutable
class OctetSequenceKey extends JWK {

  /**
   * The symmetric key value.
   */
  final Base64URL _k;

  /**
   * Creates a new octet sequence JSON Web Key (JWK) with the specified
   * parameters.
   *
   * @param k   The key value. It is represented as the Base64URL
   *            encoding of value's big endian representation. Must not
   *            be {@code null}.
   * @param use The key use, {@code null} if not specified or if the key
   *            is intended for signing as well as encryption.
   * @param ops The key operations, {@code null} if not specified.
   * @param alg The intended JOSE algorithm for the key, {@code null} if
   *            not specified.
   * @param kid The key ID. {@code null} if not specified.
   * @param x5u The X.509 certificate URL, {@code null} if not specified.
   * @param x5t The X.509 certificate thumbprint, {@code null} if not
   *            specified.
   * @param x5c The X.509 certificate chain, {@code null} if not
   *            specified.
   */
  OctetSequenceKey(final Base64URL k,
                   final KeyUse use, final Set<KeyOperation> ops, final Algorithm alg, final String kid,
                   final Uri x5u, final Base64URL x5t, final List<Base64> x5c)
  : super(KeyType.OCT, use, ops, alg, kid, x5u, x5t, x5c), _k = k {

    if (k == null) {
      throw new ArgumentError.notNull("k");
    }

  }

  /**
   * Returns the value of this octet sequence key.
   *
   * @return The key value. It is represented as the Base64URL encoding
   *         of the coordinate's big endian representation.
   */
  Base64URL getKeyValue() {

    return _k;
  }

  /**
   * Returns a copy of this octet sequence key value as a byte array.
   *
   * @return The key value as a byte array.
   */
  Uint8List toByteArray() {

    return getKeyValue().decode();
  }

  /**
   * Octet sequence (symmetric) keys are never considered public, this
   * method always returns {@code true}.
   *
   * @return {@code true}
   */
  @override
  bool isPrivate() {

    return true;
  }

  /**
   * Octet sequence (symmetric) keys are never considered public, this
   * method always returns {@code null}.
   *
   * @return {@code null}
   */
  @override
  OctetSequenceKey toPublicJWK() {

    return null;
  }

  @override
  JSONObject toJSONObject() {

    JSONObject o = super.toJSONObject();

    // Append key value
    o.put("k", _k.toString());

    return o;
  }

  /**
   * Parses an octet sequence JWK from the specified JSON object string
   * representation.
   *
   * @param s The JSON object string to parse. Must not be {@code null}.
   *
   * @return The octet sequence JWK.
   *
   * @throws ParseException If the string couldn't be parsed to an octet
   *                        sequence JWK.
   */
  static OctetSequenceKey parseFromString(final String s) {

    return parseFromJsonObject(JSONObjectUtils.parseJSONObject(s));
  }

  /**
   * Parses an octet sequence JWK from the specified JSON object
   * representation.
   *
   * @param jsonObject The JSON object to parse. Must not be
   *                   @code null}.
   *
   * @return The octet sequence JWK.
   *
   * @throws ParseException If the JSON object couldn't be parsed to an
   *                        octet sequence JWK.
   */
  static OctetSequenceKey parseFromJsonObject(final JSONObject jsonObject) {

    // Parse the mandatory parameters first
    Base64URL k = new Base64URL(JSONObjectUtils.getString(jsonObject, "k"));

    // Check key type
    KeyType kty = KeyType.parse(JSONObjectUtils.getString(jsonObject, "kty"));

    if (kty != KeyType.OCT) {

      throw new ParseError("The key type \"kty\" must be oct", 0);
    }

    // Get optional key use
    KeyUse use = null;

    if (jsonObject.containsKey("use")) {
      use = KeyUse.parse(JSONObjectUtils.getString(jsonObject, "use"));
    }

    // Get optional key operations
    Set<KeyOperation> ops = null;

    if (jsonObject.containsKey("key_ops")) {
      ops = KeyOperation.parse(JSONObjectUtils.getStringList(jsonObject, "key_ops"));
    }

    // Get optional intended algorithm
    Algorithm alg = null;

    if (jsonObject.containsKey("alg")) {
      alg = new Algorithm.withName(JSONObjectUtils.getString(jsonObject, "alg"));
    }

    // Get optional key ID
    String kid = null;

    if (jsonObject.containsKey("kid")) {
      kid = JSONObjectUtils.getString(jsonObject, "kid");
    }

    // Get optional X.509 cert URL
    Uri x5u = null;

    if (jsonObject.containsKey("x5u")) {
      x5u = JSONObjectUtils.getURL(jsonObject, "x5u");
    }

    // Get optional X.509 cert thumbprint
    Base64URL x5t = null;

    if (jsonObject.containsKey("x5t")) {
      x5t = new Base64URL(JSONObjectUtils.getString(jsonObject, "x5t"));
    }

    // Get optional X.509 cert chain
    List<Base64> x5c = null;

    if (jsonObject.containsKey("x5c")) {
      x5c = X509CertChainUtils.parseX509CertChain(JSONObjectUtils.getJSONArray(jsonObject, "x5c"));
    }

    return new OctetSequenceKey(k, use, ops, alg, kid, x5u, x5t, x5c);
  }

}
