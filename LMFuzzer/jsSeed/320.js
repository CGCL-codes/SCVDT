function f0() {
    var v0 = [];
    var v1 = [];
    v0.__proto__ = v1;
    for (var v2 = 0; v2 < 10000; ++v2) {
        v1[v2] = 1;
    }
}
f0();
