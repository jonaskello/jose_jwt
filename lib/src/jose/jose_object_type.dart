part of jose_jwt.jose;

/**
 * JOSE object type, represents the {@code typ} header parameter in plain, JSON
 * Web Signature (JWS) and JSON Web Encryption (JWE) objects. This class is
 * immutable.
 *
 * <p>Includes constants for the following standard types:
 *
 * <ul>
 *     <li>{@link #JOSE}
 *     <li>{@link #JOSE_JSON JOSE+JSON}
 *     <li>{@link #JWT}
 * </ul>
 *
 * <p>Additional types can be defined using the constructor.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-02-15)
 */
//@Immutable
class JOSEObjectType implements JSONAware {

  /**
   * Compact encoded JOSE object type.
   */
  static final JOSEObjectType JOSE = new JOSEObjectType("JOSE");

  /**
   * JSON-encoded JOSE object type..
   */
  static final JOSEObjectType JOSE_JSON = new JOSEObjectType("JOSE+JSON");

  /**
   * JSON Web Token (JWT) object type.
   */
  static final JOSEObjectType JWT = new JOSEObjectType("JWT");

  /**
   * The object type.
   */
  final String _type;

  /**
   * Creates a new JOSE object type.
   *
   * @param type The object type. Must not be {@code null}.
   */
  JOSEObjectType(this._type) {

    if (_type == null) {
      throw new ArgumentError.notNull("type");
    }

//		this.type = type;
  }

  /**
   * Gets the JOSE object type.
   *
   * @return The JOSE object type.
   */
  String getType() {
    return _type;
  }

  /**
   * Overrides {@code Object.hashCode()}.
   *
   * @return The object hash code.
   */
  @override
  int get hashCode => _type.hashCode;

  /**
   * Overrides {@code Object.equals()}.
   *
   * @param object The object to compare to.
   *
   * @return {@code true} if the objects have the same value, otherwise
   *         {@code false}.
   */
  @override
  bool operator ==(final Object object) =>
  object is JOSEObjectType &&
  this.toString() == object.toString();

  /**
   * Returns the string representation of this JOSE object type.
   *
   * @see #getType
   *
   * @return The string representation.
   */
  @override
  String toString() => _type;

	/**
	 * Returns the JSON string representation of this JOSE object type.
	 * 
	 * @return The JSON string representation.
	 */
	@override
	String toJsonString() {

		StringBuffer sb = new StringBuffer();
		sb.write('"');
//    sb.write(JSONObject.escape(_type));
    sb.write(_type);
		sb.write('"');
		return sb.toString();
	}

}
