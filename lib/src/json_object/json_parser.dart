part of jose_jwt.json_object;

class JSONParser {

  static final int USE_HI_PRECISION_FLOAT = 1;

  JSONParser(int x) {
    // TODO
  }

  JSONObject parse(String str) {
    var map = JSON.decode(str);
    return new JSONObject.fromMap(map);

  }

}
