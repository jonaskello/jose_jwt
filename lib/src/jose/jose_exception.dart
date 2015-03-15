part of jose_jwt.jose;

/**
 * Javascript Object Signing and Encryption (JOSE) exception.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-09-15)
 */
class JOSEException implements Exception {

  final String message;
  final dynamic cause;

  /**
   * Creates a new JOSE exception with the specified message.
   *
   * @param message The exception message.
   */
  JOSEException(this.message) : this.cause = null;

  /**
   * Creates a new JOSE exception with the specified message and cause.
   *
   * @param message The exception message.
   * @param cause   The exception cause.
   */
  JOSEException.withCause(this.message, this.cause);

  String toString() => message;

}


