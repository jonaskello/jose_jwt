library jose_jwt.jose;

import 'dart:typed_data';
import 'package:collection/collection.dart';
import 'util.dart';
import 'errors.dart';
import 'json_object.dart';

export 'util.dart';
export 'errors.dart';
export 'json_object.dart';

part 'jose/algorithm.dart';
part 'jose/algorithm_provider.dart';
part 'jose/common_se_header.dart';
part 'jose/compression_algorithm.dart';
part 'jose/encryption_method.dart';
part 'jose/header.dart';
part 'jose/jose_exception.dart';
part 'jose/jose_object.dart';
part 'jose/jose_object_handler.dart';
part 'jose/jose_object_handler_adapter.dart';
part 'jose/jose_object_type.dart';
part 'jose/jwe_algorithm.dart';
part 'jose/jwe_crypto_parts.dart';
part 'jose/jwe_decrypter.dart';
part 'jose/jwe_encrypter.dart';
part 'jose/jwe_header.dart';
part 'jose/jwe_object.dart';
part 'jose/jws_algorithm.dart';
part 'jose/jws_algorithm_provider.dart';
part 'jose/jws_header.dart';
part 'jose/jws_object.dart';
part 'jose/jws_signer.dart';
part 'jose/jws_verifier.dart';
part 'jose/payload.dart';
part 'jose/plain_header.dart';
part 'jose/plain_object.dart';
part 'jose/requirement.dart';

/*
/**
 * Javascript Object Signing and Encryption (JOSE) classes.
 *
 * <p>This package provides representation, compact serialisation and parsing
 * for the following JOSE objects:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.PlainObject Plaintext (unsecured) JOSE
 *         objects}.
 *     <li>{@link com.nimbusds.jose.JWSObject JSON Web Signature (JWS)
 *         objects}.
 *     <li>{@link com.nimbusds.jose.JWEObject JSON Web Encryption (JWE)
 *         objects}.
 *     <li>{@link com.nimbusds.jose.jwk.JWK JSON Web Key (JWK) objects}.
 * </ul>
 *
 * <p>References:
 *
 * <ul>
 *     <li>http://tools.ietf.org/wg/jose/
 * </ul>
 */
package com.nimbusds.jose;
