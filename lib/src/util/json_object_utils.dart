part of jose_jwt.util;
/*
/**
 * JSON object helper methods for parsing and typed retrieval of member values.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-08)
 */
class JSONObjectUtils {


  /**
   * Parses a JSON object.
   *
   * <p>Specific JSON to Java entity mapping (as per JSON Smart):
   *
   * <ul>
   *     <li>JSON true|false map to {@code java.lang.Boolean}.
   *     <li>JSON numbers map to {@code java.lang.Number}.
   *         <ul>
   *             <li>JSON integer numbers map to {@code long}.
   *             <li>JSON fraction numbers map to {@code double}.
   *         </ul>
   *     <li>JSON strings map to {@code java.lang.String}.
   *     <li>JSON arrays map to {@code net.minidev.json.JSONArray}.
   *     <li>JSON objects map to {@code net.minidev.json.JSONObject}.
   * </ul>
   *
   * @param s The JSON object string to parse. Must not be {@code null}.
   *
   * @return The JSON object.
   *
   * @throws ParseException If the string cannot be parsed to a valid JSON
   *                        object.
   */
  static JSONObject parseJSONObject(final String s) {
    throw new UnimplementedError();
/*
		Object o = null;

		try {
			o = new JSONParser(JSONParser.USE_HI_PRECISION_FLOAT).parse(s);

		} catch (net.minidev.json.parser.ParseException e) {

			throw new ParseException("Invalid JSON: " + e.getMessage(), 0);
		}

		if (o instanceof JSONObject) {
			return (JSONObject)o;
		} else {
			throw new ParseException("JSON entity is not an object", 0);
		}
*/
  }


  /**
   * Gets a generic member of a JSON object.
   *
   * @param o     The JSON object. Must not be {@code null}.
   * @param key   The JSON object member key. Must not be {@code null}.
   * @param clazz The expected class of the JSON object member value. Must
   *              not be {@code null}.
   *
   * @return The JSON object member value.
   *
   * @throws ParseException If the value is missing, {@code null} or not
   *                        of the expected type.
   */
//	@SuppressWarnings("unchecked")
//  private static <T> T _getGeneric(final JSONObject o, final String key, final Class<T> clazz)
  static dynamic _getGeneric(final JSONObject o, final String key, final Type clazz) {
//    throw new UnimplementedError();

    if (!o.containsKey(key)) {
      throw new ParseError("Missing JSON object member with key \"" + key + "\"", 0);
    }

    if (o.get(key) == null) {
      throw new ParseError("JSON object member with key \"" + key + "\" has null value", 0);
    }

    Object value = o.get(key);

//		if (! clazz.isAssignableFrom(value.getClass())) {
//			throw new ParseError("Unexpected type of JSON object member with key \"" + key + "\"", 0);
//		}

//    return (T)value;
    return value;
/*
*/
  }

  /**
   * Gets a boolean member of a JSON object.
   *
   * @param o   The JSON object. Must not be {@code null}.
   * @param key The JSON object member key. Must not be {@code null}.
   *
   * @return The member value.
   *
   * @throws ParseException If the value is missing, {@code null} or not
   *                        of the expected type.
   */
  static bool getBoolean(final JSONObject o, final String key) {

    return _getGeneric(o, key, bool);
  }


  /**
   * Gets an number member of a JSON object as {@code int}.
   *
   * @param o   The JSON object. Must not be {@code null}.
   * @param key The JSON object member key. Must not be {@code null}.
   *
   * @return The member value.
   *
   * @throws ParseException If the value is missing, {@code null} or not
   *                        of the expected type.
   */
  static int getInt(final JSONObject o, final String key) {

    return (_getGeneric(o, key, num) as num).toInt();
  }

//  /**
//   * Gets a number member of a JSON object as {@code long}.
//   *
//   * @param o   The JSON object. Must not be {@code null}.
//   * @param key The JSON object member key. Must not be {@code null}.
//   *
//   * @return The member value.
//   *
//   * @throws ParseException If the value is missing, {@code null} or not
//   *                        of the expected type.
//   */
//  static long getLong(final JSONObject o, final String key) {
//
//    return _getGeneric(o, key, num).longValue();
//  }

//  /**
//   * Gets a number member of a JSON object {@code float}.
//   *
//   * @param o   The JSON object. Must not be {@code null}.
//   * @param key The JSON object member key. Must not be {@code null}.
//   *
//   * @return The member value.
//   *
//   * @throws ParseException If the value is missing, {@code null} or not
//   *                        of the expected type.
//   */
//  static float getFloat(final JSONObject o, final String key) {
//
//    return _getGeneric(o, key, num).floatValue();
//  }

  /**
   * Gets a number member of a JSON object as {@code double}.
   *
   * @param o   The JSON object. Must not be {@code null}.
   * @param key The JSON object member key. Must not be {@code null}.
   *
   * @return The member value.
   *
   * @throws ParseException If the value is missing, {@code null} or not
   *                        of the expected type.
   */
  static double getDouble(final JSONObject o, final String key) {

    return _getGeneric(o, key, num).doubleValue();
  }

  /**
   * Gets a string member of a JSON object.
   *
   * @param o   The JSON object. Must not be {@code null}.
   * @param key The JSON object member key. Must not be {@code null}.
   *
   * @return The member value.
   *
   * @throws ParseException If the value is missing, {@code null} or not
   *                        of the expected type.
   */
  static String getString(final JSONObject o, final String key) {

    return _getGeneric(o, key, String);
  }

  /**
   * Gets a string member of a JSON object as {@code java.net.URL}.
   *
   * @param o   The JSON object. Must not be {@code null}.
   * @param key The JSON object member key. Must not be {@code null}.
   *
   * @return The member value.
   *
   * @throws ParseException If the value is missing, {@code null} or not
   *                        of the expected type.
   */
//  static URL getURL(final JSONObject o, final String key) {
  static Uri getURL(final JSONObject o, final String key) {

    try {
      return Uri.parse(_getGeneric(o, key, String));

    } catch (e) {
      // MalformedURLException
      throw new ParseError(e.getMessage(), 0);
    }
  }

  /**
   * Gets a JSON array member of a JSON object.
   *
   * @param o   The JSON object. Must not be {@code null}.
   * @param key The JSON object member key. Must not be {@code null}.
   *
   * @return The member value.
   *
   * @throws ParseException If the value is missing, {@code null} or not
   *                        of the expected type.
   */
  static JSONArray getJSONArray(final JSONObject o, final String key) {

    return _getGeneric(o, key, JSONArray);
  }

  /**
   * Gets a string array member of a JSON object.
   *
   * @param o   The JSON object. Must not be {@code null}.
   * @param key The JSON object member key. Must not be {@code null}.
   *
   * @return The member value.
   *
   * @throws ParseException If the value is missing, {@code null} or not
   *                        of the expected type.
   */
  static List<String> getStringArray(final JSONObject o, final String key) {

    JSONArray jsonArray = getJSONArray(o, key);

    try {
      return jsonArray.toArray(const []);

    } catch (e) {
//ArrayStoreException
      throw new ParseError("JSON object member with key \"" + key + "\" is not an array of strings", 0);
    }
  }

  /**
   * Gets a string list member of a JSON object
   *
   * @param o   The JSON object. Must not be {@code null}.
   * @param key The JSON object member key. Must not be {@code null}.
   *
   * @return The member value.
   *
   * @throws ParseException If the value is missing, {@code null} or not
   *                        of the expected type.
   */
  static List<String> getStringList(final JSONObject o, final String key) {

    List<String> array = getStringArray(o, key);

    return array.toList(growable:false);

  }

  /**
   * Gets a JSON object member of a JSON object.
   *
   * @param o   The JSON object. Must not be {@code null}.
   * @param key The JSON object member key. Must not be {@code null}.
   *
   * @return The member value.
   *
   * @throws ParseException If the value is missing, {@code null} or not
   *                        of the expected type.
   */
  static JSONObject getJSONObject(final JSONObject o, final String key) {

    return _getGeneric(o, key, JSONObject);
  }

  /**
   * Prevents instantiation.
   */
  JSONObjectUtils._() {

    // Nothing to do
  }

}

*/
