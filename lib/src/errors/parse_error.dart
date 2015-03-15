part of jose_jwt.errors;

class ParseError extends Error {

  final message;
  int errorOffset;

  ParseError(this.message, errorOffset);

}
