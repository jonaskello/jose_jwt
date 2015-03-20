part of jose_jwt.util;

/**
 * X.509 certificate chain utilities.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-05-29)
 */
class X509CertChainUtils {


  /**
   * Parses an X.509 certificate chain from the specified JSON array.
   *
   * @param jsonArray The JSON array to parse. Must not be {@code null}.
   *
   * @return The X.509 certificate chain.
   *
   * @throws ParseException If the X.509 certificate chain couldn't be
   *                        parsed.
   */
  static List<Base64> parseX509CertChain(final List jsonArray) {

//    List<Base64> chain = new LinkedList();
    List<Base64> chain = new List();

    for (int i = 0; i < jsonArray.length; i++) {

      Object item = jsonArray[i];

      if (item == null) {
        throw new ParseError("The X.509 certificate at position $i must not be null", 0);
      }

      if (!(item is String)) {
        throw new ParseError("The X.509 certificate at position $i must be encoded as a Base64 string", 0);
      }

      chain.add(new Base64(item as String));
    }

    return chain;
  }


	/**
	 * Prevents public instantiation.
	 */
	X509CertChainUtils._() {}

}
