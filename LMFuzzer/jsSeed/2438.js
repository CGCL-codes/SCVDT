function f0() {
    var v0 = 0;
    var v1 = 0;
    for (var v2 = 0; v2 < 2; ++v2) {
        if (v1 > 1)
            v0 += 1 % v1;
    }
    return v0;
}
f0();
WScript.Echo('pass');
