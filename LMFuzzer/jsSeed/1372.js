function f0() {
    var v0 = 512;
    var v1 = {};
    for (var v2 = 0; v2 < v0; v2++)
        v1['a' + v2] = v2;
    v1.m = function () {
        return 0;
    };
}
f0();
f0();
