part of jose_jwt.jwt;

/**
 * JSON Web Token (JWT) claims set.
 *
 * <p>Supports all {@link #getRegisteredNames()}  registered claims} of the JWT
 * specification:
 *
 * <ul>
 *     <li>iss - Issuer
 *     <li>sub - Subject
 *     <li>aud - Audience
 *     <li>exp - Expiration Time
 *     <li>nbf - Not Before
 *     <li>iat - Issued At
 *     <li>jti - JWT ID
 * </ul>
 *
 * <p>The set may also contain {@link #setCustomClaims custom claims}; these
 * will be serialised and parsed along the registered ones.
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @version $version$ (2015-02-13)
 */
class JWTClaimsSet implements ReadOnlyJWTClaimsSet {


  static const String ISSUER_CLAIM = "iss";
  static const String SUBJECT_CLAIM = "sub";
  static const String AUDIENCE_CLAIM = "aud";
  static const String EXPIRATION_TIME_CLAIM = "exp";
  static const String NOT_BEFORE_CLAIM = "nbf";
  static const String ISSUED_AT_CLAIM = "iat";
  static const String JWT_ID_CLAIM = "jti";

  /**
   * The registered claim names.
   */
  static Set<String> REGISTERED_CLAIM_NAMES;


  /**
   * Initialises the registered claim name set.
   */
  static initRegisteredClaimNameSet() {
    if (REGISTERED_CLAIM_NAMES == null) {
      Set<String> n = new Set<String>();

      n.add(ISSUER_CLAIM);
      n.add(SUBJECT_CLAIM);
      n.add(AUDIENCE_CLAIM);
      n.add(EXPIRATION_TIME_CLAIM);
      n.add(NOT_BEFORE_CLAIM);
      n.add(ISSUED_AT_CLAIM);
      n.add(JWT_ID_CLAIM);

      REGISTERED_CLAIM_NAMES = new UnmodifiableSetView(n);
    }
  }

  /**
   * The issuer claim.
   */
  String iss = null;

  /**
   * The subject claim.
   */
  String sub = null;

  /**
   * The audience claim.
   */
  List<String> aud = null;

  /**
   * The expiration time claim.
   */
  DateTime exp = null;

  /**
   * The not-before claim.
   */
  DateTime nbf = null;

  /**
   * The issued-at claim.
   */
  DateTime iat = null;

  /**
   * The JWT ID claim.
   */
  String jti = null;

  /**
   * Custom claims.
   */
  Map<String, Object> customClaims = new Map<String, Object>();

  /**
   * Creates a new empty JWT claims set.
   */
  JWTClaimsSet() {
    initRegisteredClaimNameSet();
    // Nothing to do
  }

  /**
   * Creates a copy of the specified JWT claims set.
   *
   * @param old The JWT claims set to copy. Must not be {@code null}.
   */
  JWTClaimsSet.copyOf(final ReadOnlyJWTClaimsSet old) : super() {
    initRegisteredClaimNameSet();

    setAllClaims(old.getAllClaims());
  }

  /**
   * Gets the registered JWT claim names.
   *
   * @return The registered claim names, as a unmodifiable set.
   */
  static Set<String> getRegisteredNames() {

    return REGISTERED_CLAIM_NAMES;
  }

  @override
  String getIssuer() {

    return iss;
  }


  /**
   * Sets the issuer ({@code iss}) claim.
   *
   * @param iss The issuer claim, {@code null} if not specified.
   */
  void setIssuer(final String iss) {

    this.iss = iss;
  }

  @override
  String getSubject() {

    return sub;
  }

  /**
   * Sets the subject ({@code sub}) claim.
   *
   * @param sub The subject claim, {@code null} if not specified.
   */
  void setSubject(final String sub) {

    this.sub = sub;
  }

  @override
  List<String> getAudience() {

    return aud;
  }

  /**
   * Sets the audience ({@code aud}) claim.
   *
   * @param aud The audience claim, {@code null} if not specified.
   */
  void setAudienceList(final List<String> aud) {

    this.aud = aud;
  }


  /**
   * Sets a single-valued audience ({@code aud}) claim.
   *
   * @param aud The audience claim, {@code null} if not specified.
   */
  void setAudience(final String aud) {

    if (aud == null) {
      this.aud = null;
    } else {
      this.aud = [aud];
    }
  }


  @override
  DateTime getExpirationTime() {

    return exp;
  }


  /**
   * Sets the expiration time ({@code exp}) claim.
   *
   * @param exp The expiration time, {@code null} if not specified.
   */
  void setExpirationTime(final DateTime exp) {

    this.exp = exp;
  }


  @override
  DateTime getNotBeforeTime() {

    return nbf;
  }

  /**
   * Sets the not-before ({@code nbf}) claim.
   *
   * @param nbf The not-before claim, {@code null} if not specified.
   */
  void setNotBeforeTime(final DateTime nbf) {

    this.nbf = nbf;
  }


  @override
  DateTime getIssueTime() {

    return iat;
  }

  /**
   * Sets the issued-at ({@code iat}) claim.
   *
   * @param iat The issued-at claim, {@code null} if not specified.
   */
  void setIssueTime(final DateTime iat) {

    this.iat = iat;
  }

  @override
  String getJWTID() {

    return jti;
  }

  /**
   * Sets the JWT ID ({@code jti}) claim.
   *
   * @param jti The JWT ID claim, {@code null} if not specified.
   */
  void setJWTID(final String jti) {

    this.jti = jti;
  }

  @override
  Object getCustomClaim(final String name) {

    return customClaims[name];
  }


  /**
   * Sets a custom (non-registered) claim.
   *
   * @param name  The name of the custom claim. Must not be {@code null}.
   * @param value The value of the custom claim, should map to a valid
   *              JSON entity, {@code null} if not specified.
   *
   * @throws IllegalArgumentException If the specified custom claim name
   *                                  matches a registered claim name.
   */
  void setCustomClaim(final String name, final Object value) {

    if (getRegisteredNames().contains(name)) {

      throw new ArgumentError("The claim name \"" + name + "\" matches a registered name");
    }

    customClaims[name] = value;
  }

  @override
  Map<String, Object> getCustomClaims() {

    return new UnmodifiableMapView(customClaims);
  }

  /**
   * Sets the custom (non-registered) claims. If a claim value doesn't
   * map to a JSON entity it will be ignored during serialisation.
   *
   * @param customClaims The custom claims, empty map or {@code null} if
   *                     none.
   */
  void setCustomClaims(final Map<String, Object> customClaims) {

    if (customClaims == null) {
      this.customClaims.clear();
    } else {
      this.customClaims = customClaims;
    }
  }

  @override
  Object getClaim(final String name) {

    if (ISSUER_CLAIM == name) {
      return getIssuer();
    } else if (SUBJECT_CLAIM == name) {
      return getSubject();
    } else if (AUDIENCE_CLAIM == name) {
      return getAudience();
    } else if (EXPIRATION_TIME_CLAIM == name) {
      return getExpirationTime();
    } else if (NOT_BEFORE_CLAIM == name) {
      return getNotBeforeTime();
    } else if (ISSUED_AT_CLAIM == name) {
      return getIssueTime();
    } else if (JWT_ID_CLAIM == name) {
      return getJWTID();
    } else {
      return getCustomClaim(name);
    }
  }

  @override
  String getStringClaim(final String name) {

    Object value = getClaim(name);

    if (value == null || value is String) {
      return value as String;
    } else {
      throw new ParseError("The \"" + name + "\" claim is not a String", 0);
    }
  }

  @override
  List<String> getStringArrayClaim(final String name) {
    Object value = getClaim(name);

    if (value == null) {
      return null;
    }

    List list;

    try {
      list = getClaim(name) as List;

    } catch (e) {
      /*ClassCastException*/
      throw new ParseError("The \"" + name + "\" claim is not a list / JSON array", 0);
    }

    List<String> stringArray = new List<String>(); // [list.size()];

    for (int i = 0; i < stringArray.length; i++) {

      try {
        stringArray[i] = list[i] as String;
      } catch (e) {
        /*ClassCastException*/
        throw new ParseError("The \"" + name + "\" claim is not a list / JSON array of strings", 0);
      }
    }

    return stringArray;
  }

  List<String> getStringListClaim(final String name) {

    List<String> stringArray = getStringArrayClaim(name);

    if (stringArray == null) {
      return null;
    }

    return stringArray.toList(growable:false);
  }

  @override
  bool getBooleanClaim(final String name) {

    Object value = getClaim(name);

    if (value == null || value is bool) {
      return value as bool;
    } else {
      throw new ParseError("The \"" + name + "\" claim is not a Boolean", 0);
    }
  }

  @override
  int getIntegerClaim(final String name) {

    Object value = getClaim(name);

    if (value == null) {
      return null;
    } else if (value is num) {
      return value.toInt();
    } else {
      throw new ParseError("The \"" + name + "\" claim is not an Integer", 0);
    }
  }

//	@override
//	int getLongClaim(final String name)
//		throws ParseException {
//
//		Object value = getClaim(name);
//
//		if (value == null) {
//			return null;
//		} else if (value instanceof Number) {
//			return ((Number)value).longValue();
//		} else {
//			throw new ParseException("The \"" + name + "\" claim is not a Number", 0);
//		}
//	}

//	@override
//	Float getFloatClaim(final String name)
//		throws ParseException {
//
//		Object value = getClaim(name);
//
//		if (value == null) {
//			return null;
//		} else if (value instanceof Number) {
//			return ((Number)value).floatValue();
//		} else {
//			throw new ParseException("The \"" + name + "\" claim is not a Float", 0);
//		}
//	}

  @override
  double getDoubleClaim(final String name) {

    Object value = getClaim(name);

    if (value == null) {
      return null;
    } else if (value is num) {
      return value.toDouble();
    } else {
      throw new ParseError("The \"" + name + "\" claim is not a Double", 0);
    }
  }

  /**
   * Sets the specified claim, whether registered or custom.
   *
   * @param name  The name of the claim to set. Must not be {@code null}.
   * @param value The value of the claim to set, {@code null} if not
   *              specified.
   *
   * @throws IllegalArgumentException If the claim is registered and its
   *                                  value is not of the expected type.
   */
  void setClaim(final String name, final Object value) {

    if (ISSUER_CLAIM == name) {
      if (value == null || value is String) {
        setIssuer(value as String);
      } else {
        throw new ArgumentError("Issuer claim must be a String");
      }
    } else if (SUBJECT_CLAIM == name) {
      if (value == null || value is String) {
        setSubject(value as String);
      } else {
        throw new ArgumentError("Subject claim must be a String");
      }
    } else if (AUDIENCE_CLAIM == name) {
      if (value == null || value is List) {
        setAudienceList(value as List<String>);
      } else {
        throw new ArgumentError("Audience claim must be a List<String>");
      }
    } else if (EXPIRATION_TIME_CLAIM == name) {
      if (value == null || value is DateTime) {
        setExpirationTime(value as DateTime);
      } else {
        throw new ArgumentError("Expiration claim must be a Date");
      }
    } else if (NOT_BEFORE_CLAIM == name) {
      if (value == null || value is DateTime) {
        setNotBeforeTime(value as DateTime);
      } else {
        throw new ArgumentError("Not-before claim must be a Date");
      }
    } else if (ISSUED_AT_CLAIM == name) {
      if (value == null || value is DateTime) {
        setIssueTime(value as DateTime);
      } else {
        throw new ArgumentError("Issued-at claim must be a Date");
      }
    } else if (JWT_ID_CLAIM == name) {
      if (value == null || value is String) {
        setJWTID(value as String);
      } else {
        throw new ArgumentError("JWT-ID claim must be a String");
      }
    } else {
      setCustomClaim(name, value);
    }
  }

  @override
  Map<String, Object> getAllClaims() {

    Map<String, Object> allClaims = new Map<String, Object>();

    allClaims.addAll(customClaims);

    for (String registeredClaim in REGISTERED_CLAIM_NAMES) {

      Object value = getClaim(registeredClaim);

      if (value != null) {
        allClaims[registeredClaim] = value;
      }
    }

    return new UnmodifiableMapView(allClaims);
  }

  /**
   * Sets the claims of this JWT claims set, replacing any existing ones.
   *
   * @param newClaims The JWT claims. Must not be {@code null}.
   */
  void setAllClaims(final Map<String, Object> newClaims) {

//    for (String name in newClaims.keySet()) {
//      setClaim(name, newClaims.get(name));
//    }
    newClaims.forEach((name, value) => setClaim(name, value));
  }

  @override
  JSONObject toJSONObject() {

    JSONObject o = new JSONObject.fromMap(customClaims);

    if (iss != null) {
      o.put(ISSUER_CLAIM, iss);
    }

    if (sub != null) {
      o.put(SUBJECT_CLAIM, sub);
    }

    if (aud != null && !aud.isEmpty) {

      if (aud.length == 1) {
        o.put(AUDIENCE_CLAIM, aud[0]);
      } else {
        JSONArray audArray = new JSONArray();
        audArray.addAll(aud);
        o.put(AUDIENCE_CLAIM, audArray);
      }
    }

    if (exp != null) {
      o.put(EXPIRATION_TIME_CLAIM, exp.millisecondsSinceEpoch / 1000);
    }

    if (nbf != null) {
      o.put(NOT_BEFORE_CLAIM, nbf.millisecondsSinceEpoch / 1000);
    }

    if (iat != null) {
      o.put(ISSUED_AT_CLAIM, iat.millisecondsSinceEpoch / 1000);
    }

    if (jti != null) {
      o.put(JWT_ID_CLAIM, jti);
    }

    return o;
  }

  /**
   * Parses a JSON Web Token (JWT) claims set from the specified JSON
   * object representation.
   *
   * @param json The JSON object to parse. Must not be {@code null}.
   *
   * @return The JWT claims set.
   *
   * @throws ParseException If the specified JSON object doesn't
   *                        represent a valid JWT claims set.
   */
  static JWTClaimsSet parseFromJson(final JSONObject json) {

    JWTClaimsSet cs = new JWTClaimsSet();

    // Parse registered + custom params
    for (final String name in json.keySet()) {

      if (name == ISSUER_CLAIM) {

        cs.setIssuer(JSONObjectUtils.getString(json, ISSUER_CLAIM));

      } else if (name == SUBJECT_CLAIM) {

        cs.setSubject(JSONObjectUtils.getString(json, SUBJECT_CLAIM));

      } else if (name == AUDIENCE_CLAIM) {

        Object audValue = json.get(AUDIENCE_CLAIM);

        if (audValue is String) {
          List<String> singleAud = new List<String>();
          singleAud.add(JSONObjectUtils.getString(json, AUDIENCE_CLAIM));
          cs.setAudienceList(singleAud);
        } else if (audValue is List) {
          cs.setAudienceList(JSONObjectUtils.getStringList(json, AUDIENCE_CLAIM));
        }

      } else if (name == EXPIRATION_TIME_CLAIM) {

//        cs.setExpirationTime(new DateTime(JSONObjectUtils.getLong(json, EXPIRATION_TIME_CLAIM) * 1000));
        cs.setExpirationTime(new DateTime(JSONObjectUtils.getInt(json, EXPIRATION_TIME_CLAIM) * 1000));

      } else if (name == NOT_BEFORE_CLAIM) {

//        cs.setNotBeforeTime(new DateTime(JSONObjectUtils.getLong(json, NOT_BEFORE_CLAIM) * 1000));
        cs.setNotBeforeTime(new DateTime(JSONObjectUtils.getInt(json, NOT_BEFORE_CLAIM) * 1000));

      } else if (name == ISSUED_AT_CLAIM) {

//        cs.setIssueTime(new DateTime(JSONObjectUtils.getLong(json, ISSUED_AT_CLAIM) * 1000));
        cs.setIssueTime(new DateTime(JSONObjectUtils.getInt(json, ISSUED_AT_CLAIM) * 1000));

      } else if (name == JWT_ID_CLAIM) {

        cs.setJWTID(JSONObjectUtils.getString(json, JWT_ID_CLAIM));

      } else {
        cs.setCustomClaim(name, json.get(name));
      }
    }

    return cs;
  }

  /**
   * Parses a JSON Web Token (JWT) claims set from the specified JSON
   * object string representation.
   *
   * @param s The JSON object string to parse. Must not be {@code null}.
   *
   * @return The JWT claims set.
   *
   * @throws ParseException If the specified JSON object string doesn't
   *                        represent a valid JWT claims set.
   */
  static JWTClaimsSet parseFromJsonString(final String s) {

    return parseFromJson(JSONObjectUtils.parseJSONObject(s));
  }

  @override
  String toString() {

//    return "JWTClaimsSet [iss=" + iss + ", sub=" + sub + ", aud=" + aud + ", exp=" + exp.toString() + ", nbf=" + nbf.toString() + ", iat=" + iat.toString() + ", jti=" + jti + ", customClaims=" + customClaims + "]";
    return "JWTClaimsSet [iss=$iss,sub=$sub,aud=$aud,exp=$exp,nbf=$nbf,iat=$iat,jti=$jti, customClaims=$customClaims]";
  }

}
