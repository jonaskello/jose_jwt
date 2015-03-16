part of jose_jwt.json_object;

class JSONObject {

  Map<String, Object> _map;

  int get length {
    return _map.length;
  }

  JSONObject() {
    _map = new Map<String, Object>();
  }

  JSONObject.fromMap(Map<String, Object> map) {
    _map = map;
  }

  Set<String> keySet() {
    return _map.keys.toSet();
  }

  bool containsKey(String name) {
    return _map.containsKey(name);
  }

  void put(String name, Object value) {
    _map[name] = value;
  }

  Object get(String name) {
    return _map[name];
  }

  static String escape(String str) {
    throw new UnimplementedError();
  }

}
