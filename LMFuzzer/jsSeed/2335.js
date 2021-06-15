function f0(c, dir) {
    return dir ? c.v1 : c.v1;
}
var v0 = { v1: {} };
for (v1 = 0; v1 < 100; v1++) {
    f0(v0, 0);
    f0(v0, 1);
}
