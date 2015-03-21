part of jose_jwt.jose;

/**
 * The base class for algorithm names, with optional implementation
 * requirement. This class is immutable.
 *
 * <p>Includes constants for the following standard algorithm names:
 *
 * <ul>
 *     <li>{@link #NONE none}
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-03-27)
 */
//@Immutable
class Algorithm implements JSONAware {

  /**
   * No algorithm (plain JOSE object without signature / encryption).
   */
  static final Algorithm NONE = new Algorithm("none", Requirement.REQUIRED);

  /**
   * The algorithm name.
   */
  final String _name;

  /**
   * The implementation requirement, {@code null} if not known.
   */
  final Requirement _requirement;

  /**
   * Creates a new JOSE algorithm name.
   *
   * @param name The algorithm name. Must not be {@code null}.
   * @param req  The implementation requirement, {@code null} if not
   *             known.
   */
  Algorithm(this._name, this._requirement) {

    if (_name == null) {
      throw new ArgumentError.notNull("name");
    }

  }

  /**
   * Creates a new JOSE algorithm name.
   *
   * @param name The algorithm name. Must not be {@code null}.
   */
  Algorithm.withName(final String name) :this(name, null);


  /**
   * Gets the name of this algorithm.
   *
   * @return The algorithm name.
   */
  String getName() {
    return _name;
  }

  /**
   * Gets the implementation requirement of this algorithm.
   *
   * @return The implementation requirement, {@code null} if not known.
   */
  Requirement getRequirement() {

    return _requirement;
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
  object is Algorithm &&
  this.toString() == object.toString();

  /**
   * Returns the string representation of this algorithm.
   *
   * @see #getName
   *
   * @return The string representation.
   */
  @override
  String toString() => _name;

  /**
   * Returns the JSON string representation of this algorithm.
   *
   * @return The JSON string representation.
   */
  @override
  String toJsonString() {

    StringBuffer sb = new StringBuffer();
    sb.write('"');
    sb.write(JSONObject.escape(_name));
    sb.write('"');
    return sb.toString();
  }

}
