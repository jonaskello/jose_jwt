part of jose_jwt.jose;


/**
 * Builder for constructing JSON Web Signature (JWS) headers.
 *
 * <p>Example use:
 *
 * <pre>
 * JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.HS256).
 *                    contentType("text/plain").
 *                    customParam("exp", new Date().getTime()).
 *                    build();
 * </pre>
 */
class JWSHeaderBuilder {

  /**
   * The JWS algorithm.
   */
  final JWSAlgorithm _alg;

  /**
   * The JOSE object type.
   */
  JOSEObjectType _typ;

  /**
   * The content type.
   */
  String _cty;

  /**
   * The critical headers.
   */
  Set<String> _crit;

  /**
   * JWK Set URL.
   */
  Uri _jku;

  /**
   * JWK.
   */
  JWK _jwk;

  /**
   * X.509 certificate URL.
   */
  Uri _x5u;

  /**
   * X.509 certificate SHA-1 thumbprint.
   */
  Base64URL _x5t;

  /**
   * X.509 certificate SHA-256 thumbprint.
   */
  Base64URL _x5t256;

  /**
   * The X.509 certificate chain corresponding to the key used to
   * sign the JWS object.
   */
  List<Base64> _x5c;

  /**
   * Key ID.
   */
  String _kid;

  /**
   * Custom header parameters.
   */
  Map<String, Object> _customParams;

  /**
   * The parsed Base64URL.
   */
  Base64URL _parsedBase64URL;

  /**
   * Creates a new JWS header builder.
   *
   * @param alg The JWS algorithm ({@code alg}) parameter. Must
   *            not be "none" or {@code null}.
   */
  JWSHeaderBuilder(final JWSAlgorithm alg)
  : this._(alg, null, null, null, null, null, null, null, null, null, null, null, null);

  /**
   * Creates a new JWS header builder with the parameters from
   * the specified header.
   *
   * @param jwsHeader The JWS header to use. Must not not be
   *                  {@code null}.
   */
  JWSHeaderBuilder.fromHeader(final JWSHeader jwsHeader)
  : this._(jwsHeader.getAlgorithm(), jwsHeader.getType(), jwsHeader.getContentType(), jwsHeader.getCriticalParams(),
  jwsHeader.getCustomParams(), jwsHeader.getJWKURL(), jwsHeader.getJWK(), jwsHeader.getX509CertURL(), jwsHeader.getX509CertThumbprint(),
  jwsHeader.getX509CertSHA256Thumbprint(), jwsHeader.getX509CertChain(), jwsHeader.getKeyID(), jwsHeader.getCustomParams());

  JWSHeaderBuilder._(this._alg, this._typ, this._cty, this._crit, this._customParams, this._jku,
                     this._jwk, this._x5u, this._x5t, this._x5t256, this._x5c, this._kid,
                     this._customParams) {

    if (_alg.getName() == Algorithm.NONE.getName()) {
      throw new ArgumentError("The JWS algorithm \"alg\" cannot be \"none\"");
    }

  }

  /**
   * Sets the type ({@code typ}) parameter.
   *
   * @param typ The type parameter, {@code null} if not
   *            specified.
   *
   * @return This builder.
   */
  JWSHeaderBuilder type(final JOSEObjectType typ) {

    this._typ = typ;
    return this;
  }


  /**
   * Sets the content type ({@code cty}) parameter.
   *
   * @param cty The content type parameter, {@code null} if not
   *            specified.
   *
   * @return This builder.
   */
  JWSHeaderBuilder contentType(final String cty) {

    this._cty = cty;
    return this;
  }


  /**
   * Sets the critical header parameters ({@code crit})
   * parameter.
   *
   * @param crit The names of the critical header parameters,
   *             empty set or {@code null} if none.
   *
   * @return This builder.
   */
  JWSHeaderBuilder criticalParams(final Set<String> crit) {

    this._crit = crit;
    return this;
  }


  /**
   * Sets the JSON Web Key (JWK) Set URL ({@code jku}) parameter.
   *
   * @param jku The JSON Web Key (JWK) Set URL parameter,
   *            {@code null} if not specified.
   *
   * @return This builder.
   */
  JWSHeaderBuilder jwkURL(final Uri jku) {

    this._jku = jku;
    return this;
  }


  /**
   * Sets the JSON Web Key (JWK) ({@code jwk}) parameter.
   *
   * @param jwk The JSON Web Key (JWK) ({@code jwk}) parameter,
   *            {@code null} if not specified.
   *
   * @return This builder.
   */
  JWSHeaderBuilder jwk(final JWK jwk) {

    this._jwk = jwk;
    return this;
  }

  /**
   * Sets the X.509 certificate URL ({@code x5u}) parameter.
   *
   * @param x5u The X.509 certificate URL parameter, {@code null}
   *            if not specified.
   *
   * @return This builder.
   */
  JWSHeaderBuilder x509CertURL(final Uri x5u) {

    this._x5u = x5u;
    return this;
  }


  /**
   * Sets the X.509 certificate SHA-1 thumbprint ({@code x5t})
   * parameter.
   *
   * @param x5t The X.509 certificate SHA-1 thumbprint parameter,
   *            {@code null} if not specified.
   *
   * @return This builder.
   */
  JWSHeaderBuilder x509CertThumbprint(final Base64URL x5t) {

    this._x5t = x5t;
    return this;
  }


  /**
   * Sets the X.509 certificate SHA-256 thumbprint
   * ({@code x5t#S256}) parameter.
   *
   * @param x5t256 The X.509 certificate SHA-256 thumbprint
   *               parameter, {@code null} if not specified.
   *
   * @return This builder.
   */
  JWSHeaderBuilder x509CertSHA256Thumbprint(final Base64URL x5t256) {

    this._x5t256 = x5t256;
    return this;
  }


  /**
   * Sets the X.509 certificate chain parameter ({@code x5c})
   * corresponding to the key used to sign the JWS object.
   *
   * @param x5c The X.509 certificate chain parameter,
   *            {@code null} if not specified.
   *
   * @return This builder.
   */
  JWSHeaderBuilder x509CertChain(final List<Base64> x5c) {

    this._x5c = x5c;
    return this;
  }


  /**
   * Sets the key ID ({@code kid}) parameter.
   *
   * @param kid The key ID parameter, {@code null} if not
   *            specified.
   *
   * @return This builder.
   */
  JWSHeaderBuilder keyID(final String kid) {

    this._kid = kid;
    return this;
  }


  /**
   * Sets a custom (non-registered) parameter.
   *
   * @param name  The name of the custom parameter. Must not
   *              match a registered parameter name and must not
   *              be {@code null}.
   * @param value The value of the custom parameter, should map
   *              to a valid JSON entity, {@code null} if not
   *              specified.
   *
   * @return This builder.
   *
   * @throws IllegalArgumentException If the specified parameter
   *                                  name matches a registered
   *                                  parameter name.
   */
  JWSHeaderBuilder customParam(final String name, final Object value) {

    if (JWSHeader.getRegisteredParameterNames().contains(name)) {
      throw new ArgumentError("The parameter name \"" + name + "\" matches a registered name");
    }

    if (_customParams == null) {
      _customParams = new Map();
    }

    _customParams[name] = value;

    return this;
  }

  /**
   * Sets the custom (non-registered) parameters. The values must
   * be serialisable to a JSON entity, otherwise will be ignored.
   *
   * @param customParameters The custom parameters, empty map or
   *                         {@code null} if none.
   *
   * @return This builder.
   */
  JWSHeaderBuilder customParams(final Map<String, Object> customParameters) {

    this._customParams = customParameters;
    return this;
  }


  /**
   * Sets the parsed Base64URL.
   *
   * @param base64URL The parsed Base64URL, {@code null} if the
   *                  header is created from scratch.
   *
   * @return This builder.
   */
  JWSHeaderBuilder parsedBase64URL(final Base64URL base64URL) {

    this._parsedBase64URL = base64URL;
    return this;
  }

  /**
   * Builds a new JWS header.
   *
   * @return The JWS header.
   */
  JWSHeader build() {

    return new JWSHeader(
        _alg, _typ, _cty, _crit,
        _jku, _jwk, _x5u, _x5t, _x5t256, _x5c, _kid,
        _customParams, _parsedBase64URL);
  }

}


/**
 * JSON Web Signature (JWS) header.
 *
 * <p>Supports all {@link #getRegisteredParameterNames registered header
 * parameters} of the JWS specification:
 *
 * <ul>
 *     <li>alg
 *     <li>jku
 *     <li>jwk
 *     <li>x5u
 *     <li>x5t
 *     <li>x5t#S256
 *     <li>x5c
 *     <li>kid
 *     <li>typ
 *     <li>cty
 *     <li>crit
 * </ul>
 *
 * <p>The header may also include {@link #getCustomParams custom
 * parameters}; these will be serialised and parsed along the registered ones.
 *
 * <p>Example header of a JSON Web Signature (JWS) object using the
 * {@link JWSAlgorithm#HS256 HMAC SHA-256 algorithm}:
 *
 * <pre>
 * {
 *   "alg" : "HS256"
 * }
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-08-20)
 */
//@Immutable
class JWSHeader extends CommonSEHeader {


  /**
   * The registered parameter names.
   */
  static final Set<String> _REGISTERED_PARAMETER_NAMES = new UnmodifiableSetView(new Set.from(
      [
          "alg",
          "jku",
          "jwk",
          "x5u",
          "x5t",
          "x5t#S256",
          "x5c",
          "kid",
          "typ",
          "cty",
          "crit",
      ]
  ));


//  /**
//   * Initialises the registered parameter name set.
//   */
//  static c() {
//    Set<String> p = new Set();
//
//    p.add("alg");
//    p.add("jku");
//    p.add("jwk");
//    p.add("x5u");
//    p.add("x5t");
//    p.add("x5t#S256");
//    p.add("x5c");
//    p.add("kid");
//    p.add("typ");
//    p.add("cty");
//    p.add("crit");
//
//    REGISTERED_PARAMETER_NAMES = new UnmodifiableSet(p);
//  }


  /**
   * Creates a new minimal JSON Web Signature (JWS) header.
   *
   * <p>Note: Use {@link PlainHeader} to create a header with algorithm
   * {@link Algorithm#NONE none}.
   *
   * @param alg The JWS algorithm ({@code alg}) parameter. Must not be
   *            "none" or {@code null}.
   */
  JWSHeader.fromAlg(final JWSAlgorithm alg) : this(alg, null, null, null, null, null, null, null, null, null, null, null, null);

  /**
   * Creates a new JSON Web Signature (JWS) header.
   *
   * <p>Note: Use {@link PlainHeader} to create a header with algorithm
   * {@link Algorithm#NONE none}.
   *
   * @param alg             The JWS algorithm ({@code alg}) parameter.
   *                        Must not be "none" or {@code null}.
   * @param typ             The type ({@code typ}) parameter,
   *                        {@code null} if not specified.
   * @param cty             The content type ({@code cty}) parameter,
   *                        {@code null} if not specified.
   * @param crit            The names of the critical header
   *                        ({@code crit}) parameters, empty set or
   *                        {@code null} if none.
   * @param jku             The JSON Web Key (JWK) Set URL ({@code jku})
   *                        parameter, {@code null} if not specified.
   * @param jwk             The X.509 certificate URL ({@code jwk})
   *                        parameter, {@code null} if not specified.
   * @param x5u             The X.509 certificate URL parameter
   *                        ({@code x5u}), {@code null} if not specified.
   * @param x5t             The X.509 certificate SHA-1 thumbprint
   *                        ({@code x5t}) parameter, {@code null} if not
   *                        specified.
   * @param x5t256          The X.509 certificate SHA-256 thumbprint
   *                        ({@code x5t#S256}) parameter, {@code null} if
   *                        not specified.
   * @param x5c             The X.509 certificate chain ({@code x5c})
   *                        parameter, {@code null} if not specified.
   * @param kid             The key ID ({@code kid}) parameter,
   *                        {@code null} if not specified.
   * @param customParams    The custom parameters, empty map or
   *                        {@code null} if none.
   * @param parsedBase64URL The parsed Base64URL, {@code null} if the
   *                        header is created from scratch.
   */
  JWSHeader(final JWSAlgorithm alg,
            final JOSEObjectType typ,
            final String cty,
            final Set<String> crit,
            final Uri jku,
            final JWK jwk,
            final Uri x5u,
            final Base64URL x5t,
            final Base64URL x5t256,
            final List<Base64> x5c,
            final String kid,
            final Map<String, Object> customParams,
            final Base64URL parsedBase64URL) : super(alg, typ, cty, crit, jku, jwk, x5u, x5t, x5t256, x5c, kid, customParams, parsedBase64URL) {

    if (alg.getName() == Algorithm.NONE.getName()) {
      throw new ArgumentError("The JWS algorithm \"alg\" cannot be \"none\"");
    }
  }

  /**
   * Deep copy constructor.
   *
   * @param jwsHeader The JWS header to copy. Must not be {@code null}.
   */
  JWSHeader.deepCopy(final JWSHeader jwsHeader) :
  this(
      jwsHeader.getAlgorithm(),
      jwsHeader.getType(),
      jwsHeader.getContentType(),
      jwsHeader.getCriticalParams(),
      jwsHeader.getJWKURL(),
      jwsHeader.getJWK(),
      jwsHeader.getX509CertURL(),
      jwsHeader.getX509CertThumbprint(),
      jwsHeader.getX509CertSHA256Thumbprint(),
      jwsHeader.getX509CertChain(),
      jwsHeader.getKeyID(),
      jwsHeader.getCustomParams(),
      jwsHeader.getParsedBase64URL()
  );

  /**
   * Gets the registered parameter names for JWS headers.
   *
   * @return The registered parameter names, as an unmodifiable set.
   */
  static Set<String> getRegisteredParameterNames() {

    return _REGISTERED_PARAMETER_NAMES;
  }

  /**
   * Gets the algorithm ({@code alg}) parameter.
   *
   * @return The algorithm parameter.
   */
  @override
  JWSAlgorithm getAlgorithm() {

    return super.getAlgorithm() as JWSAlgorithm;
  }

  /**
   * Parses a JWS header from the specified JSON object.
   *
   * @param jsonObject The JSON object to parse. Must not be
   *                   {@code null}.
   *
   * @return The JWS header.
   *
   * @throws ParseException If the specified JSON object doesn't
   *                        represent a valid JWS header.
   */
  static JWSHeader parseJsonObject(final JSONObject jsonObject) {

    return parseJsonObjectAndUrl(jsonObject, null);
  }

  /**
   * Parses a JWS header from the specified JSON object.
   *
   * @param jsonObject      The JSON object to parse. Must not be
   *                        {@code null}.
   * @param parsedBase64URL The original parsed Base64URL, {@code null}
   *                        if not applicable.
   *
   * @return The JWS header.
   *
   * @throws ParseException If the specified JSON object doesn't
   *                        represent a valid JWS header.
   */
  static JWSHeader parseJsonObjectAndUrl(final JSONObject jsonObject,
                                         final Base64URL parsedBase64URL) {

    // Get the "alg" parameter
    Algorithm alg = Header.parseAlgorithm(jsonObject);

    if (!(alg is JWSAlgorithm)) {
      throw new ParseError("The algorithm \"alg\" header parameter must be for signatures", 0);
    }

    JWSHeaderBuilder header = new JWSHeaderBuilder(alg as JWSAlgorithm).parsedBase64URL(parsedBase64URL);

    // Parse optional + custom parameters
    for (final String name in jsonObject.keySet()) {

      if ("alg" == name) {
        // skip
      } else if ("typ" == name) {
        header = header.type(new JOSEObjectType(JSONObjectUtils.getString(jsonObject, name)));
      } else if ("cty" == name) {
        header = header.contentType(JSONObjectUtils.getString(jsonObject, name));
      } else if ("crit" == name) {
        header = header.criticalParams(new Set.from(JSONObjectUtils.getStringList(jsonObject, name)));
      } else if ("jku" == name) {
        header = header.jwkURL(JSONObjectUtils.getURL(jsonObject, name));
      } else if ("jwk" == name) {
        header = header.jwk(JWK.parseFromJsonObject(JSONObjectUtils.getJSONObject(jsonObject, name)));
      } else if ("x5u" == name) {
        header = header.x509CertURL(JSONObjectUtils.getURL(jsonObject, name));
      } else if ("x5t" == name) {
        header = header.x509CertThumbprint(new Base64URL(JSONObjectUtils.getString(jsonObject, name)));
      } else if ("x5t#S256" == name) {
        header = header.x509CertSHA256Thumbprint(new Base64URL(JSONObjectUtils.getString(jsonObject, name)));
      } else if ("x5c" == name) {
        header = header.x509CertChain(X509CertChainUtils.parseX509CertChain(JSONObjectUtils.getJSONArray(jsonObject, name)));
      } else if ("kid" == name) {
        header = header.keyID(JSONObjectUtils.getString(jsonObject, name));
      } else {
        header = header.customParam(name, jsonObject.get(name));
      }
    }

    return header.build();
  }

  /**
   * Parses a JWS header from the specified JSON object string.
   *
   * @param jsonString The JSON string to parse. Must not be
   *                   {@code null}.
   *
   * @return The JWS header.
   *
   * @throws ParseException If the specified JSON object string doesn't
   *                        represent a valid JWS header.
   */
  static JWSHeader parseJsonString(final String jsonString) {

    return parseJsonStringAndUrl(jsonString, null);
  }

  /**
   * Parses a JWS header from the specified JSON object string.
   *
   * @param jsonString      The JSON string to parse. Must not be
   *                        {@code null}.
   * @param parsedBase64URL The original parsed Base64URL, {@code null}
   *                        if not applicable.
   *
   * @return The JWS header.
   *
   * @throws ParseException If the specified JSON object string doesn't
   *                        represent a valid JWS header.
   */
  static JWSHeader parseJsonStringAndUrl(final String jsonString,
                                         final Base64URL parsedBase64URL) {

    return parseJsonObjectAndUrl(JSONObjectUtils.parseJSONObject(jsonString), parsedBase64URL);
  }

  /**
   * Parses a JWS header from the specified Base64URL.
   *
   * @param base64URL The Base64URL to parse. Must not be {@code null}.
   *
   * @return The JWS header.
   *
   * @throws ParseException If the specified Base64URL doesn't represent
   *                        a valid JWS header.
   */
  static JWSHeader parseBase64Url(final Base64URL base64URL) {

    return parseJsonStringAndUrl(base64URL.decodeToString(), base64URL);
  }

}
