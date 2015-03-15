part of jose_jwt.jose;

/**
 * JSON Web Encryption (JWE) header.
 *
 * <p>Supports all {@link #getRegisteredParameterNames registered header
 * parameters} of the JWE specification:
 *
 * <ul>
 *     <li>alg
 *     <li>enc
 *     <li>epk
 *     <li>zip
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
 *     <li>apu
 *     <li>apv
 *     <li>p2s
 *     <li>p2c
 *     <li>iv
 *     <li>authTag
 * </ul>
 *
 * <p>The header may also include {@link #getCustomParams custom
 * parameters}; these will be serialised and parsed along the registered ones.
 *
 * <p>Example header:
 *
 * <pre>
 * {
 *   "alg" : "RSA1_5",
 *   "enc" : "A128CBC-HS256"
 * }
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-08-20)
 */
//@Immutable
class JWEHeader extends CommonSEHeader {

  /**
   * The registered parameter names.
   */
  static final Set<String> _REGISTERED_PARAMETER_NAMES = new UnmodifiableSetView(new Set<String>.from(
      [
          "alg",
          "enc",
          "epk",
          "zip",
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
          "apu",
          "apv",
          "p2s",
          "p2c",
          "iv",
          "authTag",
      ]
  ));

//	/**
//	 * Initialises the registered parameter name set.
//	 */
//	static initRegistredParameterNames() {
//		Set<String> p = new Set<String>();
//
//		p.add("alg");
//		p.add("enc");
//		p.add("epk");
//		p.add("zip");
//		p.add("jku");
//		p.add("jwk");
//		p.add("x5u");
//		p.add("x5t");
//		p.add("x5t#S256");
//		p.add("x5c");
//		p.add("kid");
//		p.add("typ");
//		p.add("cty");
//		p.add("crit");
//		p.add("apu");
//		p.add("apv");
//		p.add("p2s");
//		p.add("p2c");
//		p.add("iv");
//		p.add("authTag");
//
//		_REGISTERED_PARAMETER_NAMES = new UnmodifiableSetView(p);
//	}

  /**
   * The encryption method ({@code enc}) parameter.
   */
  final EncryptionMethod _enc;


  /**
   * The ephemeral key ({@code epk}) parameter.
   */
  final ECKey _epk;


  /**
   * The compression algorithm ({@code zip}) parameter.
   */
  final CompressionAlgorithm _zip;


  /**
   * The agreement PartyUInfo ({@code apu}) parameter.
   */
  final Base64URL _apu;


  /**
   * The agreement PartyVInfo ({@code apv}) parameter.
   */
  final Base64URL _apv;


  /**
   * The PBES2 salt ({@code p2s}) parameter.
   */
  final Base64URL _p2s;


  /**
   * The PBES2 count ({@code p2c}) parameter.
   */
  final int _p2c;


  /**
   * The initialisation vector ({@code iv}) parameter.
   */
  final Base64URL _iv;


  /**
   * The authentication tag ({@code tag}) parameter.
   */
  final Base64URL _tag;

  /**
   * Creates a new minimal JSON Web Encryption (JWE) header.
   *
   * <p>Note: Use {@link PlainHeader} to create a header with algorithm
   * {@link Algorithm#NONE none}.
   *
   * @param alg The JWE algorithm parameter. Must not be "none" or
   *            {@code null}.
   * @param enc The encryption method parameter. Must not be
   *            {@code null}.
   */
  JWEHeader.minimal(final JWEAlgorithm alg, final EncryptionMethod enc) :
  this(
      alg, enc,
      null, null, null, null, null, null, null, null, null, null,
      null, null, null, null, null, 0,
      null, null,
      null, null);

  /**
   * Creates a new JSON Web Encryption (JWE) header.
   *
   * <p>Note: Use {@link PlainHeader} to create a header with algorithm
   * {@link Algorithm#NONE none}.
   *
   * @param alg             The JWE algorithm ({@code alg}) parameter.
   *                        Must not be "none" or {@code null}.
   * @param enc             The encryption method parameter. Must not be
   *                        {@code null}.
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
   * @param epk             The Ephemeral Public Key ({@code epk})
   *                        parameter, {@code null} if not specified.
   * @param zip             The compression algorithm ({@code zip})
   *                        parameter, {@code null} if not specified.
   * @param apu             The agreement PartyUInfo ({@code apu})
   *                        parameter, {@code null} if not specified.
   * @param apv             The agreement PartyVInfo ({@code apv})
   *                        parameter, {@code null} if not specified.
   * @param p2s             The PBES2 salt ({@code p2s}) parameter,
   *                        {@code null} if not specified.
   * @param p2c             The PBES2 count ({@code p2c}) parameter, zero
   *                        if not specified. Must not be negative.
   * @param iv              The initialisation vector ({@code iv})
   *                        parameter, {@code null} if not specified.
   * @param tag             The authentication tag ({@code tag})
   *                        parameter, {@code null} if not specified.
   * @param customParams    The custom parameters, empty map or
   *                        {@code null} if none.
   * @param parsedBase64URL The parsed Base64URL, {@code null} if the
   *                        header is created from scratch.
   */
  JWEHeader(final Algorithm alg,
            this._enc,
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
            this._epk,
            this._zip,
            this._apu,
            this._apv,
            this._p2s,
            this._p2c,
            this._iv,
            this._tag,
            final Map<String, Object> customParams,
            final Base64URL parsedBase64URL) : super(alg, typ, cty, crit, jku, jwk, x5u, x5t, x5t256, x5c, kid, customParams, parsedBase64URL) {

    if (_alg.getName() == Algorithm.NONE.getName()) {
      throw new ArgumentError("The JWE algorithm cannot be \"none\"");
    }

    if (_enc == null) {
      throw new ArgumentError.notNull("enc");
    }

//    this.enc = enc;
//    this.epk = epk;
//    this.zip = zip;
//    this.apu = apu;
//    this.apv = apv;
//    this.p2s = p2s;
//    this.p2c = p2c;
//    this.iv = iv;
//    this.tag = tag;
  }

  /**
   * Deep copy constructor.
   *
   * @param jweHeader The JWE header to copy. Must not be {@code null}.
   */
  JWEHeader.deepCopy(final JWEHeader jweHeader) :

  this(
      jweHeader.getAlgorithm(),
      jweHeader.getEncryptionMethod(),
      jweHeader.getType(),
      jweHeader.getContentType(),
      jweHeader.getCriticalParams(),
      jweHeader.getJWKURL(),
      jweHeader.getJWK(),
      jweHeader.getX509CertURL(),
      jweHeader.getX509CertThumbprint(),
      jweHeader.getX509CertSHA256Thumbprint(),
      jweHeader.getX509CertChain(),
      jweHeader.getKeyID(),
      jweHeader.getEphemeralPublicKey(),
      jweHeader.getCompressionAlgorithm(),
      jweHeader.getAgreementPartyUInfo(),
      jweHeader.getAgreementPartyVInfo(),
      jweHeader.getPBES2Salt(),
      jweHeader.getPBES2Count(),
      jweHeader.getIV(),
      jweHeader.getAuthTag(),
      jweHeader.getCustomParams(),
      jweHeader.getParsedBase64URL()
  );


  /**
   * Gets the registered parameter names for JWE headers.
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
  JWEAlgorithm getAlgorithm() {

    return super.getAlgorithm() as JWEAlgorithm;
  }

  /**
   * Gets the encryption method ({@code enc}) parameter.
   *
   * @return The encryption method parameter.
   */
  EncryptionMethod getEncryptionMethod() {

    return _enc;
  }


  /**
   * Gets the Ephemeral Public Key ({@code epk}) parameter.
   *
   * @return The Ephemeral Public Key parameter, {@code null} if not
   *         specified.
   */
  ECKey getEphemeralPublicKey() {

    return _epk;
  }


  /**
   * Gets the compression algorithm ({@code zip}) parameter.
   *
   * @return The compression algorithm parameter, {@code null} if not
   *         specified.
   */
  CompressionAlgorithm getCompressionAlgorithm() {

    return _zip;
  }


  /**
   * Gets the agreement PartyUInfo ({@code apu}) parameter.
   *
   * @return The agreement PartyUInfo parameter, {@code null} if not
   *         specified.
   */
  Base64URL getAgreementPartyUInfo() {

    return _apu;
  }


  /**
   * Gets the agreement PartyVInfo ({@code apv}) parameter.
   *
   * @return The agreement PartyVInfo parameter, {@code null} if not
   *         specified.
   */
  Base64URL getAgreementPartyVInfo() {

    return _apv;
  }


  /**
   * Gets the PBES2 salt ({@code p2s}) parameter.
   *
   * @return The PBES2 salt parameter, {@code null} if not specified.
   */
  Base64URL getPBES2Salt() {

    return _p2s;
  }

  /**
   * Gets the PBES2 count ({@code p2c}) parameter.
   *
   * @return The PBES2 count parameter, zero if not specified.
   */
  int getPBES2Count() {

    return _p2c;
  }


  /**
   * Gets the initialisation vector ({@code iv}) parameter.
   *
   * @return The initialisation vector, {@code null} if not specified.
   */
  Base64URL getIV() {

    return _iv;
  }

  /**
   * Gets the authentication tag ({@code tag}) parameter.
   *
   * @return The authentication tag, {@code null} if not specified.
   */
  Base64URL getAuthTag() {

    return _tag;
  }

  @override
  Set<String> getIncludedParams() {

    Set<String> includedParameters = super.getIncludedParams();

    if (_enc != null) {
      includedParameters.add("enc");
    }

    if (_epk != null) {
      includedParameters.add("epk");
    }

    if (_zip != null) {
      includedParameters.add("zip");
    }

    if (_apu != null) {
      includedParameters.add("apu");
    }

    if (_apv != null) {
      includedParameters.add("apv");
    }

    if (_p2s != null) {
      includedParameters.add("p2s");
    }

    if (_p2c > 0) {
      includedParameters.add("p2c");
    }

    if (_iv != null) {
      includedParameters.add("iv");
    }

    if (_tag != null) {
      includedParameters.add("tag");
    }

    return includedParameters;
  }

  @override
  JSONObject toJSONObject() {

    JSONObject o = super.toJSONObject();

    if (_enc != null) {
      o.put("enc", _enc.toString());
    }

    if (_epk != null) {
      o.put("epk", _epk.toJSONObject());
    }

    if (_zip != null) {
      o.put("zip", _zip.toString());
    }

    if (_apu != null) {
      o.put("apu", _apu.toString());
    }

    if (_apv != null) {
      o.put("apv", _apv.toString());
    }

    if (_p2s != null) {
      o.put("p2s", _p2s.toString());
    }

    if (_p2c > 0) {
      o.put("p2c", _p2c);
    }

    if (_iv != null) {
      o.put("iv", _iv.toString());
    }

    if (_tag != null) {
      o.put("tag", _tag.toString());
    }

    return o;
  }

  /**
   * Parses an encryption method ({@code enc}) parameter from the
   * specified JWE header JSON object.
   *
   * @param json The JSON object to parse. Must not be {@code null}.
   *
   * @return The encryption method.
   *
   * @throws ParseException If the {@code enc} parameter couldn't be
   *                        parsed.
   */
  static EncryptionMethod _parseEncryptionMethod(final JSONObject json) {

    return EncryptionMethod.parse(JSONObjectUtils.getString(json, "enc"));
  }

  /**
   * Parses a JWE header from the specified JSON object.
   *
   * @param jsonObject The JSON object to parse. Must not be
   *                   {@code null}.
   *
   * @return The JWE header.
   *
   * @throws ParseException If the specified JSON object doesn't
   *                        represent a valid JWE header.
   */
  static JWEHeader parseJsonObject(final JSONObject jsonObject) {

    return parseJsonObjectAndUrl(jsonObject, null);
  }

  /**
   * Parses a JWE header from the specified JSON object.
   *
   * @param jsonObject      The JSON object to parse. Must not be
   *                        {@code null}.
   * @param parsedBase64URL The original parsed Base64URL, {@code null}
   *                        if not applicable.
   *
   * @return The JWE header.
   *
   * @throws ParseException If the specified JSON object doesn't
   *                        represent a valid JWE header.
   */
  static JWEHeader parseJsonObjectAndUrl(final JSONObject jsonObject,
                                         final Base64URL parsedBase64URL) {

    // Get the "alg" parameter
    Algorithm alg = Header.parseAlgorithm(jsonObject);

    if (!(alg is JWEAlgorithm)) {
      throw new ParseError("The algorithm \"alg\" header parameter must be for encryption", 0);
    }

    // Get the "enc" parameter
    EncryptionMethod enc = _parseEncryptionMethod(jsonObject);

    JWEHeaderBuilder header = new JWEHeaderBuilder(alg as JWEAlgorithm, enc).parsedBase64URL(parsedBase64URL);

    // Parse optional + custom parameters
    for (final String name in jsonObject.keySet()) {

      if ("alg" == name) {
        // skip
      } else if ("enc" == name) {
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
        header = header.jwk(JWK.parse(JSONObjectUtils.getJSONObject(jsonObject, name)));
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
      } else if ("epk" == name) {
        header = header.ephemeralPublicKey(ECKey.parse(JSONObjectUtils.getJSONObject(jsonObject, name)));
      } else if ("zip" == name) {
        header = header.compressionAlgorithm(new CompressionAlgorithm(JSONObjectUtils.getString(jsonObject, name)));
      } else if ("apu" == name) {
        header = header.agreementPartyUInfo(new Base64URL(JSONObjectUtils.getString(jsonObject, name)));
      } else if ("apv" == name) {
        header = header.agreementPartyVInfo(new Base64URL(JSONObjectUtils.getString(jsonObject, name)));
      } else if ("p2s" == name) {
        header = header.pbes2Salt(new Base64URL(JSONObjectUtils.getString(jsonObject, name)));
      } else if ("p2c" == name) {
        header = header.pbes2Count(JSONObjectUtils.getInt(jsonObject, name));
      } else if ("iv" == name) {
        header = header.iv(new Base64URL(JSONObjectUtils.getString(jsonObject, name)));
      } else if ("tag" == name) {
        header = header.authTag(new Base64URL(JSONObjectUtils.getString(jsonObject, name)));
      } else {
        header = header.customParam(name, jsonObject.get(name));
      }
    }

    return header.build();
  }

  /**
   * Parses a JWE header from the specified JSON object string.
   *
   * @param jsonString The JSON object string to parse. Must not be {@code null}.
   *
   * @return The JWE header.
   *
   * @throws ParseException If the specified JSON object string doesn't
   *                        represent a valid JWE header.
   */
  static JWEHeader parseJsonString(final String jsonString) {

    return parseJsonObjectAndUrl(JSONObjectUtils.parseJSONObject(jsonString), null);
  }

  /**
   * Parses a JWE header from the specified JSON object string.
   *
   * @param jsonString      The JSON string to parse. Must not be
   *                        {@code null}.
   * @param parsedBase64URL The original parsed Base64URL, {@code null}
   *                        if not applicable.
   *
   * @return The JWE header.
   *
   * @throws ParseException If the specified JSON object string doesn't
   *                        represent a valid JWE header.
   */
  static JWEHeader parseJsonStringAndUrl(final String jsonString, final Base64URL parsedBase64URL) {

    return parseJsonObjectAndUrl(JSONObjectUtils.parseJSONObject(jsonString), parsedBase64URL);
  }

  /**
   * Parses a JWE header from the specified Base64URL.
   *
   * @param base64URL The Base64URL to parse. Must not be {@code null}.
   *
   * @return The JWE header.
   *
   * @throws ParseException If the specified Base64URL doesn't represent
   *                        a valid JWE header.
   */
  static JWEHeader parseBase64Url(final Base64URL base64URL) {

    return parseJsonStringAndUrl(base64URL.decodeToString(), base64URL);
  }

}

/**
 * Builder for constructing JSON Web Encryption (JWE) headers.
 *
 * <p>Example use:
 *
 * <pre>
 * JWEHeader header = new JWEHeader.Builder(JWEAlgorithm.RSA1_5, EncryptionMethod.A128GCM).
 *                    contentType("text/plain").
 *                    customParam("exp", new Date().getTime()).
 *                    build();
 * </pre>
 */
class JWEHeaderBuilder {

  /**
   * The JWE algorithm.
   */
  final JWEAlgorithm _alg;

  /**
   * The encryption method.
   */
  final EncryptionMethod _enc;

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
   * The ephemeral key.
   */
  ECKey _epk;


  /**
   * The compression algorithm.
   */
  CompressionAlgorithm _zip;


  /**
   * The agreement PartyUInfo.
   */
  Base64URL _apu;


  /**
   * The agreement PartyVInfo.
   */
  Base64URL _apv;


  /**
   * The PBES2 salt.
   */
  Base64URL _p2s;


  /**
   * The PBES2 count.
   */
  int _p2c;


  /**
   * The initialisation vector.
   */
  Base64URL _iv;


  /**
   * The authentication authTag.
   */
  Base64URL _tag;


  /**
   * Custom header parameters.
   */
  Map<String, Object> _customParams;


  /**
   * The parsed Base64URL.
   */
  Base64URL _parsedBase64URL;


  /**
   * Creates a new JWE header builder.
   *
   * @param alg The JWE algorithm ({@code alg}) parameter. Must
   *            not be "none" or {@code null}.
   * @param enc The encryption method. Must not be {@code null}.
   */
  JWEHeaderBuilder(final JWEAlgorithm alg, final EncryptionMethod enc)
  : this._(
      alg, enc, null, null, null, null, null, null,
      null, null, null, null, null, null,
      null, null, null, null, null, null,
      null, null
  );

  /**
   * Creates a new JWE header builder with the parameters from
   * the specified header.
   *
   * @param jweHeader The JWE header to use. Must not not be
   *                  {@code null}.
   */
  JWEHeaderBuilder.from(final JWEHeader jweHeader)
  : this._(
      jweHeader.getAlgorithm(),
      jweHeader.getEncryptionMethod(),
      jweHeader.getType(),
      jweHeader.getContentType(),
      jweHeader.getCriticalParams(),
      jweHeader.getCustomParams(),
      jweHeader.getJWKURL(),
      jweHeader.getJWK(),
      jweHeader.getX509CertURL(),
      jweHeader.getX509CertThumbprint(),
      jweHeader.getX509CertSHA256Thumbprint(),
      jweHeader.getX509CertChain(),
      jweHeader.getKeyID(),
      jweHeader.getEphemeralPublicKey(),
      jweHeader.getCompressionAlgorithm(),
      jweHeader.getAgreementPartyUInfo(),
      jweHeader.getAgreementPartyVInfo(),
      jweHeader.getPBES2Salt(),
      jweHeader.getPBES2Count(),
      jweHeader.getIV(),
      jweHeader.getAuthTag(),
      jweHeader.getCustomParams()
  );

  JWEHeaderBuilder._(this._alg, this._enc, this._typ, this._cty, this._crit, this._customParams,
                     this._jku, this._jwk, this._x5u, this._x5t, this._x5t256, this._x5c,
                     this._kid, this._epk, this._zip, this._apu, this._apv, this._p2s, this._p2c,
                     this._iv, this._tag, this._customParams)
  {
    if (_alg.getName() == Algorithm.NONE.getName()) {
      throw new ArgumentError("The JWE algorithm \"alg\" cannot be \"none\"");
    }

    if (_enc == null) {
      throw new ArgumentError.notNull("enc");
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
  JWEHeaderBuilder type(final JOSEObjectType typ) {

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
  JWEHeaderBuilder contentType(final String cty) {

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
  JWEHeaderBuilder criticalParams(final Set<String> crit) {

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
  JWEHeaderBuilder jwkURL(final Uri jku) {

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
  JWEHeaderBuilder jwk(final JWK jwk) {

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
  JWEHeaderBuilder x509CertURL(final Uri x5u) {

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
  JWEHeaderBuilder x509CertThumbprint(final Base64URL x5t) {

    this._x5t = x5t;
    return this;
  }


  /**
   * Sets the X.509 certificate SHA-256 thumbprint
   * ({@code x5t#s256}) parameter.
   *
   * @param x5t256 The X.509 certificate SHA-256 thumbprint
   *               parameter, {@code null} if not specified.
   *
   * @return This builder.
   */
  JWEHeaderBuilder x509CertSHA256Thumbprint(final Base64URL x5t256) {

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
  JWEHeaderBuilder x509CertChain(final List<Base64> x5c) {

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
  JWEHeaderBuilder keyID(final String kid) {

    this._kid = kid;
    return this;
  }


  /**
   * Sets the Ephemeral Public Key ({@code epk}) parameter.
   *
   * @param epk The Ephemeral Public Key parameter, {@code null}
   *            if not specified.
   *
   * @return This builder.
   */
  JWEHeaderBuilder ephemeralPublicKey(final ECKey epk) {

    this._epk = epk;
    return this;
  }


  /**
   * Sets the compression algorithm ({@code zip}) parameter.
   *
   * @param zip The compression algorithm parameter, {@code null}
   *            if not specified.
   *
   * @return This builder.
   */
  JWEHeaderBuilder compressionAlgorithm(final CompressionAlgorithm zip) {

    this._zip = zip;
    return this;
  }


  /**
   * Sets the agreement PartyUInfo ({@code apu}) parameter.
   *
   * @param apu The agreement PartyUInfo parameter, {@code null}
   *            if not specified.
   *
   * @return This builder.
   */
  JWEHeaderBuilder agreementPartyUInfo(final Base64URL apu) {

    this._apu = apu;
    return this;
  }


  /**
   * Sets the agreement PartyVInfo ({@code apv}) parameter.
   *
   * @param apv The agreement PartyVInfo parameter, {@code null}
   *            if not specified.
   *
   * @return This builder.
   */
  JWEHeaderBuilder agreementPartyVInfo(final Base64URL apv) {

    this._apv = apv;
    return this;
  }


  /**
   * Sets the PBES2 salt ({@code p2s}) parameter.
   *
   * @param p2s The PBES2 salt parameter, {@code null} if not
   *            specified.
   *
   * @return This builder.
   */
  JWEHeaderBuilder pbes2Salt(final Base64URL p2s) {

    this._p2s = p2s;
    return this;
  }


  /**
   * Sets the PBES2 count ({@code p2c}) parameter.
   *
   * @param p2c The PBES2 count parameter, zero if not specified.
   *            Must not be negative.
   *
   * @return This builder.
   */
  JWEHeaderBuilder pbes2Count(final int p2c) {

    if (p2c < 0)
      throw new ArgumentError("The PBES2 count parameter must not be negative");

    this._p2c = p2c;
    return this;
  }


  /**
   * Sets the initialisation vector ({@code iv}) parameter.
   *
   * @param iv The initialisation vector, {@code null} if not
   *           specified.
   *
   * @return This builder.
   */
  JWEHeaderBuilder iv(final Base64URL iv) {

    this._iv = iv;
    return this;
  }


  /**
   * Sets the authentication tag ({@code tag}) parameter.
   *
   * @param tag The authentication tag, {@code null} if not
   *            specified.
   *
   * @return This builder.
   */
  JWEHeaderBuilder authTag(final Base64URL tag) {

    this._tag = tag;
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
  JWEHeaderBuilder customParam(final String name, final Object value) {

    if (JWEHeader.getRegisteredParameterNames().contains(name)) {
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
  JWEHeaderBuilder customParams(final Map<String, Object> customParameters) {

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
  JWEHeaderBuilder parsedBase64URL(final Base64URL base64URL) {

    this._parsedBase64URL = base64URL;
    return this;
  }

  /**
   * Builds a new JWE header.
   *
   * @return The JWE header.
   */
  JWEHeader build() {

    return new JWEHeader(
        _alg, _enc, _typ, _cty, _crit,
        _jku, _jwk, _x5u, _x5t, _x5t256, _x5c, _kid,
        _epk, _zip, _apu, _apv, _p2s, _p2c,
        _iv, _tag,
        _customParams, _parsedBase64URL);
  }

}
