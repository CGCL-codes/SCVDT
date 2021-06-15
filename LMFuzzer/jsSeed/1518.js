function f0() {
    var v0 = { a: 0 };
    var v1 = 3;
    for (var v2 = 0; v2 < 3; ++v2)
        v0.a = 0 / (v1 >>>= 1);
    return v0.a;
}
;
WScript.Echo(f0());
