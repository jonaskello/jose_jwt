library jose_jwt.jose.all_tests;

import 'package:unittest/unittest.dart';
import 'algorithm_test.dart' as algorithm_test;
import 'encryption_method_test.dart' as encryption_method_test;
import 'header_test.dart' as header_test;
import 'jose_object_handler_adapter_test.dart' as jose_object_handler_adapter_test;
import 'jose_object_handler_test.dart' as jose_object_handler_test;
import 'jose_object_test.dart' as jose_object_test;
import 'jose_object_type_test.dart' as jose_object_type_test;
import 'jwe_algorithm_test.dart' as jwe_algorithm_test;
import 'jwe_crypto_parts_test.dart' as jwe_crypto_parts_test;
import 'jwe_header_test.dart' as jwe_header_test;
import 'jwe_object_test.dart' as jwe_object_test;
import 'jws_algorithm_test.dart' as jws_algorithm_test;
import 'jws_header_test.dart' as jws_header_test;
import 'jws_object_test.dart' as jws_object_test;
import 'payload_test.dart' as payload_test;
import 'plain_header_test.dart' as plain_header_test;
import 'plain_object_test.dart' as plain_object_test;

void main() {
  group('AlgorithmTest', algorithm_test.main);
  group('EncryptionMethodTest', encryption_method_test.main);
  group('HeaderTest', header_test.main);
  group('JOSEObjectHandlerAdapterTest', jose_object_handler_adapter_test.main);
  group('JOSEObjectHandlerTest', jose_object_handler_test.main);
  group('JOSEObjectTest', jose_object_test.main);
  group('JOSEObjectTypeTest', jose_object_type_test.main);
  group('JWEAlgorithmTest', jwe_algorithm_test.main);
  group('JWECryptoPartsTest', jwe_crypto_parts_test.main);
  group('JWEHeaderTest', jwe_header_test.main);
  group('JWEObjectTest', jwe_object_test.main);
  group('JWSAlgorithmTest', jws_algorithm_test.main);
  group('JWSHeaderTest', jws_header_test.main);
  group('JWSObjectTest', jws_object_test.main);
  group('PayloadTest', payload_test.main);
  group('PlainHeaderTest', plain_header_test.main);
  group('PlainObjectTest', plain_object_test.main);
}
