part of jose_jwt.jose;

/**
 * Compression algorithm name, represents the {@code zip} header parameter in
 * JSON Web Encryption (JWE) objects. This class is immutable.
 *
 * <p>Includes a constant for the standard DEFLATE compression algorithm:
 *
 * <ul>
 *     <li>{@link #DEF}
 * </ul>
 *
 * <p>Additional compression algorithm names can be defined using the
 * constructor.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-01-15)
 */
//@Immutable
class CompressionAlgorithm implements JSONAware {


  /**
   * DEFLATE Compressed Data Format Specification version 1.3, as
   * described in RFC 1951.
   */
  static final CompressionAlgorithm DEF = new CompressionAlgorithm("DEF");


  /**
   * The algorithm name.
   */
  final String _name;

  /**
   * Creates a new compression algorithm with the specified name.
   *
   * @param name The compression algorithm name. Must not be {@code null}.
   */
  CompressionAlgorithm(this._name) {

    if (_name == null) {
      throw new ArgumentError.notNull("name");
    }

//		this.name = name;
  }

  /**
   * Gets the name of this compression algorithm.
   *
   * @return The compression algorithm name.
   */
  String getName() {

    return _name;
  }

  /**
   * Overrides {@code Object.hashCode()}.
   *
   * @return The object hash code.
   */
  @override
  int get hashCode => _name.hashCode;

  /**
   * Overrides {@code Object.equals()}.
   *
   * @param object The object to compare to.
   *
   * @return {@code true} if the objects have the same value, otherwise
   *         {@code false}.
   */
  @override
  bool operator ==(Object object) =>
  object is CompressionAlgorithm &&
  this.toString() == object.toString();

  /**
   * Returns the string representation of this compression algorithm.
   *
   * @see #getName
   *
   * @return The string representation.
   */
  @override
  String toString() => _name;

  /**
   * Returns the JSON string representation of this compression algorithm.
   *
   * @return The JSON string representation.
   */
  @override
  String toJSONString() {

    StringBuffer sb = new StringBuffer();
    sb.write('"');
    sb.write(JSONObject.escape(_name));
    sb.write('"');
    return sb.toString();
  }

}
