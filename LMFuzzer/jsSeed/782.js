function f0() {
    var v0 = new Int8Array(500);
    for (var v1 = 500; v1 < 1000; ++v1) {
        v0[v1] = 0;
    }
}
f0();
f0();
WScript.Echo('PASSED');
