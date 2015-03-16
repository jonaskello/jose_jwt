part of jose_jwt.jose;

/**
 * Enumeration of the original data types used to create a
 * {@link Payload}.
 */
enum PayloadOrigin {

/**
 * The payload was created from a JSON object.
 */
JSON,

/**
 * The payload was created from a string.
 */
STRING,

/**
 * The payload was created from a byte array.
 */
BYTE_ARRAY,

/**
 * The payload was created from a Base64URL-encoded object.
 */
BASE64URL,

/**
 * The payload was created from a JWS object.
 */
JWS_OBJECT,

/**
 * The payload was created from a signed JSON Web Token (JWT).
 */
SIGNED_JWT
}

/**
 * Payload with JSON object, string, byte array, Base64URL, JWS object and
 * signed JWT views. Represents the original object that was signed with JWS or
 * encrypted with JWE. This class is immutable.
 *
 * <p>UTF-8 is the character set for all conversions between strings and byte
 * arrays.
 *
 * <p>Conversion relations:
 *
 * <pre>
 * JSONObject <=> String <=> Base64URL
 *                       <=> byte[]
 *                       <=> JWSObject
 *                       <=> SignedJWT
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-10-28)
 */
//@Immutable
class Payload {

  /**
   * UTF-8 is the character set for all conversions between strings and
   * byte arrays.
   */
  static final Encoding _CHARSET = UTF8; //Charset.forName("UTF-8");


  /**
   * The original payload data type.
   */
  PayloadOrigin _origin;


  /**
   * The JSON object view.
   */
  final JSONObject _jsonObject;


  /**
   * The string view.
   */
  final String _string;


  /**
   * The byte array view.
   */
  final Uint8List _bytes;

  /**
   * The Base64URL view.
   */
  final Base64URL _base64URL;


  /**
   * The JWS object view.
   */
  final JWSObject _jwsObject;


  /**
   * The signed JWT view.
   */
  final SignedJWT _signedJWT;

  /**
   * Converts a byte array to a string using {@link #CHARSET}.
   *
   * @param bytes The byte array to convert. May be {@code null}.
   *
   * @return The resulting string, {@code null} if conversion failed.
   */
  static String _byteArrayToString(final Uint8List bytes) {

    if (bytes == null) {

      return null;
    }

//    return new String(bytes, CHARSET);
    return _CHARSET.decode(bytes);
  }

  /**
   * Converts a string to a byte array using {@link #CHARSET}.
   *
   * @param string The string to convert. May be {@code null}.
   *
   * @return The resulting byte array, {@code null} if conversion failed.
   */
  static Uint8List _stringToByteArray(final String string) {

    if (string == null) {
      return null;
    }

//    return string.getBytes(CHARSET);
    return _CHARSET.encode(string);
  }

  /**
   * Creates a new payload from the specified JSON object.
   *
   * @param jsonObject The JSON object representing the payload. Must not
   *                   be {@code null}.
   */
  Payload.fromJsonObject(final JSONObject jsonObject) :
  _jsonObject = jsonObject,
  _string = null,
  _bytes = null,
  _base64URL = null,
  _jwsObject = null,
  _signedJWT = null,
  _origin = PayloadOrigin.JSON
  {
    if (jsonObject == null) {
      throw new ArgumentError.notNull("jsonObject");
    }
  }

  /**
   * Creates a new payload from the specified string.
   *
   * @param string The string representing the payload. Must not be
   *               {@code null}.
   */
  Payload.fromString(final String string)
  :
  _jsonObject = null,
  _string = string,
  _bytes = null,
  _base64URL = null,
  _jwsObject = null,
  _signedJWT = null,
  _origin = PayloadOrigin.STRING
  {
    if (string == null) {
      throw new ArgumentError.notNull("string");
    }
  }

  /**
   * Creates a new payload from the specified byte array.
   *
   * @param bytes The byte array representing the payload. Must not be
   *              {@code null}.
   */
  Payload.fromBytes(final Uint8List bytes)
  : _jsonObject = null,
  _string = null,
  _bytes = bytes,
  _base64URL = null,
  _jwsObject = null,
  _signedJWT = null,
  _origin = PayloadOrigin.BYTE_ARRAY
  {
    if (bytes == null) {
      throw new ArgumentError.notNull("bytes");
    }
  }

  /**
   * Creates a new payload from the specified Base64URL-encoded object.
   *
   * @param base64URL The Base64URL-encoded object representing the
   *                  payload. Must not be {@code null}.
   */
  Payload(final Base64URL base64URL)
  : _jsonObject = null,
  _string = null,
  _bytes = null,
  _base64URL = base64URL,
  _jwsObject = null,
  _signedJWT = null,
  _origin = PayloadOrigin.BASE64URL {
    if (base64URL == null) {
      throw new ArgumentError.notNull("base64URL");
    }
  }

  /**
   * Creates a new payload from the specified JWS object. Intended for
   * signed then encrypted JOSE objects.
   *
   * @param jwsObject The JWS object representing the payload. Must be in
   *                  a signed state and not {@code null}.
   */
  Payload.fromJWSObject(final JWSObject jwsObject)
  :
  _jsonObject = null,
  _string = null,
  _bytes = null,
  _base64URL = null,
  _jwsObject = jwsObject,
  _signedJWT = null,
  _origin = PayloadOrigin.JWS_OBJECT

  {
    if (jwsObject == null) {
      throw new ArgumentError.notNull("jwsObject");
    }

    if (jwsObject.getState() == JWSObjectState.UNSIGNED) {
      throw new ArgumentError("The JWS object must be signed");
    }
  }

  /**
   * Creates a new payload from the specified signed JSON Web Token
   * (JWT). Intended for signed then encrypted JWTs.
   *
   * @param signedJWT The signed JWT representing the payload. Must be in
   *                  a signed state and not {@code null}.
   */
  Payload.fromSignedJwt(final SignedJWT signedJWT)
  : _jsonObject = null,
  _string = null,
  _bytes = null,
  _base64URL = null,
  this._signedJWT = signedJWT,
  _jwsObject = signedJWT, // The signed JWT is also a JWS
  _origin = PayloadOrigin.SIGNED_JWT
  {
    if (signedJWT == null) {
      throw new ArgumentError.notNull("signedJWT");
    }
    if (signedJWT.getState() == JWSObjectState.UNSIGNED) {
      throw new ArgumentError.notNull("The JWT must be signed");
    }
  }

  /**
   * Gets the original data type used to create this payload.
   *
   * @return The payload origin.
   */
  PayloadOrigin getOrigin() {

    return _origin;
  }

  /**
   * Returns a JSON object view of this payload.
   *
   * @return The JSON object view, {@code null} if the payload couldn't
   *         be converted to a JSON object.
   */
  JSONObject toJSONObject() {

    if (_jsonObject != null) {
      return _jsonObject;
    }

    // Convert

    String s = toString();

    if (s == null) {
      // to string conversion failed
      return null;
    }

    try {
      return JSONObjectUtils.parseJSONObject(s);

    } catch (e) {
      // Payload not a JSON object
      if (e is ParseError)
        return null;
    }
  }

  /**
   * Returns a string view of this payload.
   *
   * @return The string view.
   */
  @override
  String toString() {

    if (_string != null) {
      return _string;
    }

    // Convert
    if (_jwsObject != null) {

      if (_jwsObject.getParsedString() != null) {
        return _jwsObject.getParsedString();
      } else {
        return _jwsObject.serialize();
      }

    } else if (_jsonObject != null) {

      return _jsonObject.toString();

    } else if (_bytes != null) {

      return _byteArrayToString(_bytes);

    } else if (_base64URL != null) {

      return _base64URL.decodeToString();
    } else {
      return null;
      // should never happen
    }
  }

  /**
   * Returns a byte array view of this payload.
   *
   * @return The byte array view.
   */
  Uint8List toBytes() {

    if (_bytes != null) {
      return _bytes;
    }

    // Convert
    if (_base64URL != null) {
      return _base64URL.decode();
    }

    return _stringToByteArray(toString());
  }

  /**
   * Returns a Base64URL view of this payload.
   *
   * @return The Base64URL view.
   */
  Base64URL toBase64URL() {

    if (_base64URL != null) {
      return _base64URL;
    }

    // Convert
    return Base64URL.encodeBytes(toBytes());
  }

  /**
   * Returns a JWS object view of this payload. Intended for signed then
   * encrypted JOSE objects.
   *
   * @return The JWS object view, {@code null} if the payload couldn't
   *         be converted to a JWS object.
   */
  JWSObject toJWSObject() {

    if (_jwsObject != null) {
      return _jwsObject;
    }

    try {
      return JWSObject.parse(toString());

    } catch (e) {
      if (e is ParseError)
        return null;
    }
  }

  /**
   * Returns a signed JSON Web Token (JWT) view of this payload. Intended
   * for signed then encrypted JWTs.
   *
   * @return The signed JWT view, {@code null} if the payload couldn't be
   *         converted to a signed JWT.
   */
  SignedJWT toSignedJWT() {

    if (_signedJWT != null) {
      return _signedJWT;
    }

    try {
      return SignedJWT.parse(toString());

    } catch (e) {
      if (e is ParseError)
        return null;
    }
  }

}
