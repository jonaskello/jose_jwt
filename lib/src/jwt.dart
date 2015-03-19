library jose_jwt.jwt;

import 'dart:convert';
import 'package:collection/collection.dart';
import 'jose.dart';

part 'jwt/encrypted_jwt.dart';
part 'jwt/jwt.dart';
part 'jwt/jwt_claims_set.dart';
part 'jwt/jwt_handler.dart';
part 'jwt/jwt_handler_adapter.dart';
part 'jwt/jwt_parser.dart';
part 'jwt/plain_jwt.dart';
part 'jwt/read_only_jwt_claims_set.java.dart';
part 'jwt/signed_jwt.dart';

/**
 * JSON Web Token (JWT) classes.
 *
 * <p>This package provides representation, compact serialisation and parsing
 * for the following JWT objects:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jwt.PlainJWT Plain JWTs}.
 *     <li>{@link com.nimbusds.jwt.SignedJWT Signed JWTs}.
 *     <li>{@link com.nimbusds.jwt.EncryptedJWT Encrypted JWTs}.
 * </ul>
 *
 * <p>References:
 *
 * <ul>
 *     <li>http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-32
 * </ul>
 */



