for (var v0 = 0; v0 < 2000; v0++) {
    Object.prototype['X' + v0] = true;
}
var v1 = new Map();
v1.set(Object.prototype, 23);
var v2 = {};
v1.set(v2, 42);
