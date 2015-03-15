part of jose_jwt.util;

/**
 * String utilities.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-05-16)
 */
class StringUtils {

  /**
   * Converts the specified string to a byte array.
   *
   * @param s The input string to convert. Must be UTF-8 encoded and not
   *          {@code null}.
   *
   * @return The resulting byte array.
   */
  static Uint8List toByteArray(final String s) {
    throw new UnimplementedError();
    /*
		return s.getBytes(Charset.forName("UTF-8"));
		*/
  }


  /**
   * Prevents public instantiation.
   */
  StringUtils._() {

  }
/*
	*/

}
