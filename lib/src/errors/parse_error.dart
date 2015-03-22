part of jose_jwt.errors;

class ParseError extends Error {

  final message;
  final int errorOffset;

  ParseError(this.message, this.errorOffset);

  @override toString() => this.message;

}
