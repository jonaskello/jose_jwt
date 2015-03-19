part of jose_jwt.jose;

/**
 * The base abstract class for plaintext, JSON Web Signature (JWS) and JSON Web
 * Encryption (JWE) headers.
 *
 * <p>The header may also include {@link #getCustomParams custom
 * parameters}; these will be serialised and parsed along the registered ones.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-08-21)
 */
abstract class Header {

  /**
   * The algorithm ({@code alg}) parameter.
   */
  final Algorithm _alg;

  /**
   * The JOSE object type ({@code typ}) parameter.
   */
  final JOSEObjectType _typ;

  /**
   * The content type ({@code cty}) parameter.
   */
  final String _cty;

  /**
   * The critical headers ({@code crit}) parameter.
   */
  final Set<String> _crit;

  /**
   * Custom header parameters.
   */
  final Map<String, Object> _customParams;

  /**
   * Empty custom parameters constant.
   */
  static final Map<String, Object> _EMPTY_CUSTOM_PARAMS =
  new UnmodifiableMapView(new Map<String, Object>());

  /**
   * The original parsed Base64URL, {@code null} if the header was
   * created from scratch.
   */
  final Base64URL _parsedBase64URL;

  /**
   * Creates a new abstract header.
   *
   * @param alg             The algorithm ({@code alg}) parameter. Must
   *                        not be {@code null}.
   * @param typ             The type ({@code typ}) parameter,
   *                        {@code null} if not specified.
   * @param cty             The content type ({@code cty}) parameter,
   *                        {@code null} if not specified.
   * @param crit            The names of the critical header
   *                        ({@code crit}) parameters, empty set or
   *                        {@code null} if none.
   * @param customParams    The custom parameters, empty map or
   *                        {@code null} if none.
   * @param parsedBase64URL The parsed Base64URL, {@code null} if the
   *                        header is created from scratch.
   */
  Header(this._alg,
         this._typ,
         this._cty,
         Set<String> crit,
         final Map<String, Object> customParams,
         this._parsedBase64URL) :
  _crit =crit != null ? new UnmodifiableSetView(new Set.from([crit])) : null,
  _customParams = customParams != null ? new UnmodifiableMapView(new Map.from(customParams)) : _EMPTY_CUSTOM_PARAMS {

    if (_alg == null) {
      throw new ArgumentError.notNull("alg");
    }

//		this.alg = alg;
//		this.typ = typ;
//    this.cty = cty;

//    if (crit != null) {
//      // Copy and make unmodifiable
//      this.crit = new UnmodifiableSetView(new Set.from([crit]));
//    } else {
//      this.crit = null;
//    }

//    if (customParams != null) {
//      // Copy and make unmodifiable
//      this.customParams = new UnmodifiableMapView(new Map.from(customParams));
//    } else {
//      this.customParams = EMPTY_CUSTOM_PARAMS;
//    }

//		this.parsedBase64URL = parsedBase64URL;
  }

  /**
   * Deep copy constructor.
   *
   * @param header The header to copy. Must not be {@code null}.
   */
  Header.deepCopy(final Header header)
  : this(
      header.getAlgorithm(),
      header.getType(),
      header.getContentType(),
      header.getCriticalParams(),
      header.getCustomParams(),
      header.getParsedBase64URL());

  /**
   * Gets the algorithm ({@code alg}) parameter.
   *
   * @return The algorithm parameter.
   */
  Algorithm getAlgorithm() {

    return _alg;
  }

  /**
   * Gets the type ({@code typ}) parameter.
   *
   * @return The type parameter, {@code null} if not specified.
   */
  JOSEObjectType getType() {

    return _typ;
  }

  /**
   * Gets the content type ({@code cty}) parameter.
   *
   * @return The content type parameter, {@code null} if not specified.
   */
  String getContentType() {

    return _cty;
  }

  /**
   * Gets the critical header parameters ({@code crit}) parameter.
   *
   * @return The names of the critical header parameters, as a
   *         unmodifiable set, {@code null} if not specified.
   */
  Set<String> getCriticalParams() {

    return _crit;
  }

  /**
   * Gets a custom (non-registered) parameter.
   *
   * @param name The name of the custom parameter. Must not be
   *             {@code null}.
   *
   * @return The custom parameter, {@code null} if not specified.
   */
  Object getCustomParam(final String name) {

    return _customParams[name];
  }


  /**
   * Gets the custom (non-registered) parameters.
   *
   * @return The custom parameters, as a unmodifiable map, empty map if
   *         none.
   */
  Map<String, Object> getCustomParams() {

    return _customParams;
  }

  /**
   * Gets the original Base64URL used to create this header.
   *
   * @return The parsed Base64URL, {@code null} if the header was created
   *         from scratch.
   */
  Base64URL getParsedBase64URL() {

    return _parsedBase64URL;
  }

  /**
   * Gets the names of all included parameters (registered and custom) in
   * the header instance.
   *
   * @return The included parameters.
   */
  Set<String> getIncludedParams() {

    Set<String> includedParameters =
    new Set.from(getCustomParams().keys);

    includedParameters.add("alg");

    if (getType() != null) {
      includedParameters.add("typ");
    }

    if (getContentType() != null) {
      includedParameters.add("cty");
    }

    if (getCriticalParams() != null && !getCriticalParams().isEmpty) {
      includedParameters.add("crit");
    }

    return includedParameters;
  }

  /**
   * Returns a JSON object representation of the header. All custom
   * parameters are included if they serialise to a JSON entity and
   * their names don't conflict with the registered ones.
   *
   * @return The JSON object representation of the header.
   */
  JSONObject toJSONObject() {

    // Include custom parameters, they will be overwritten if their
    // names match specified registered ones
    JSONObject o = new JSONObject.fromMap(_customParams);

    // Alg is always defined
    o.put("alg", _alg.toString());

    if (_typ != null) {
      o.put("typ", _typ.toString());
    }

    if (_cty != null) {
      o.put("cty", _cty);
    }

    if (_crit != null && !_crit.isEmpty) {
      o.put("crit", new List.from(_crit));
    }

    return o;
  }

  /**
   * Returns a JSON string representation of the header. All custom
   * parameters will be included if they serialise to a JSON entity and
   * their names don't conflict with the registered ones.
   *
   * @return The JSON string representation of the header.
   */
  String toString() {

    return toJSONObject().toString();
  }

  /**
   * Returns a Base64URL representation of the header. If the header was
   * parsed always returns the original Base64URL (required for JWS
   * validation and authenticated JWE decryption).
   *
   * @return The original parsed Base64URL representation of the header,
   *         or a new Base64URL representation if the header was created
   *         from scratch.
   */
  Base64URL toBase64URL() {

    if (_parsedBase64URL == null) {

      // Header was created from scratch, return new Base64URL
      return Base64URL.encodeString(toString());

    } else {

      // Header was parsed, return original Base64URL
      return _parsedBase64URL;
    }
  }

  /**
   * Parses an algorithm ({@code alg}) parameter from the specified
   * header JSON object. Intended for initial parsing of plain, JWS and
   * JWE headers.
   *
   * <p>The algorithm type (none, JWS or JWE) is determined by inspecting
   * the algorithm name for "none" and the presence of an "enc"
   * parameter.
   *
   * @param json The JSON object to parse. Must not be {@code null}.
   *
   * @return The algorithm, an instance of {@link Algorithm#NONE},
   *         {@link JWSAlgorithm} or {@link JWEAlgorithm}.
   *
   * @throws ParseException If the {@code alg} parameter couldn't be
   *                        parsed.
   */
  static Algorithm parseAlgorithm(final Map json) {

    String algName = JSONUtils.getString(json, "alg");

    // Infer algorithm type

    if (algName == Algorithm.NONE.getName()) {
      // Plain
      return Algorithm.NONE;
    } else if (json.containsKey("enc")) {
      // JWE
      return JWEAlgorithm.parse(algName);
    } else {
      // JWS
      return JWSAlgorithm.parse(algName);
    }
  }

  /**
   * Parses a {@link PlainHeader}, {@link JWSHeader} or {@link JWEHeader}
   * from the specified JSON object.
   *
   * @param jsonObject      The JSON object to parse. Must not be
   *                        {@code null}.
   *
   * @return The header.
   *
   * @throws ParseException If the specified JSON object doesn't
   *                        represent a valid header.
   */
  static Header parseJsonObject(final Map jsonObject) {

    return parseJsonObjectAndUrl(jsonObject, null);
  }

  /**
   * Parses a {@link PlainHeader}, {@link JWSHeader} or {@link JWEHeader}
   * from the specified JSON object.
   *
   * @param jsonObject      The JSON object to parse. Must not be
   *                        {@code null}.
   * @param parsedBase64URL The original parsed Base64URL, {@code null}
   *                        if not applicable.
   *
   * @return The header.
   *
   * @throws ParseException If the specified JSON object doesn't
   *                        represent a valid header.
   */
  static Header parseJsonObjectAndUrl(final Map jsonObject,
                             final Base64URL parsedBase64URL) {

    Algorithm alg = parseAlgorithm(jsonObject);

    if (alg == Algorithm.NONE) {

      return PlainHeader.parseJsonObjectAndUrl(jsonObject, parsedBase64URL);

    } else if (alg is JWSAlgorithm) {

      return JWSHeader.parseJsonObjectAndUrl(jsonObject, parsedBase64URL);

    } else if (alg is JWEAlgorithm) {

      return JWEHeader.parseJsonObjectAndUrl(jsonObject, parsedBase64URL);

    } else {

      throw new StateError("Unexpected algorithm type: $alg");
    }
  }

  /**
   * Parses a {@link PlainHeader}, {@link JWSHeader} or {@link JWEHeader}
   * from the specified JSON object string.
   *
   * @param jsonString      The JSON object string to parse. Must not be
   *                        {@code null}.
   *
   * @return The header.
   *
   * @throws ParseException If the specified JSON object string doesn't
   *                        represent a valid header.
   */
  static Header parseJsonString(final String jsonString) {

    return parseJsonStringAndUrl(jsonString, null);
  }

  /**
   * Parses a {@link PlainHeader}, {@link JWSHeader} or {@link JWEHeader}
   * from the specified JSON object string.
   *
   * @param jsonString      The JSON object string to parse. Must not be
   *                        {@code null}.
   * @param parsedBase64URL The original parsed Base64URL, {@code null}
   *                        if not applicable.
   *
   * @return The header.
   *
   * @throws ParseException If the specified JSON object string doesn't
   *                        represent a valid header.
   */
  static Header parseJsonStringAndUrl(final String jsonString,
                      final Base64URL parsedBase64URL) {

    Map jsonObject = JSON.decode(jsonString);

    return parseJsonObjectAndUrl(jsonObject, parsedBase64URL);
  }

  /**
   * Parses a {@link PlainHeader}, {@link JWSHeader} or {@link JWEHeader}
   * from the specified Base64URL.
   *
   * @param base64URL The Base64URL to parse. Must not be {@code null}.
   *
   * @return The header.
   *
   * @throws ParseException If the specified Base64URL doesn't represent
   *                        a valid header.
   */
  static Header parseBase64Url(final Base64URL base64URL) {

    return parseJsonStringAndUrl(base64URL.decodeToString(), base64URL);
  }

}
