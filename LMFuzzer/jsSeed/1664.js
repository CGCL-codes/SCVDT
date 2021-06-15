function f0() {
    var v0 = {
        a: 1,
        b: 1,
        c: 1,
        d: 1,
        get e() {
            return 1000;
        }
    };
    for (var v1 in v0)
        v0[v1];
}
f0();
