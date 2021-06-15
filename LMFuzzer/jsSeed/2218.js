function f0() {
    var v0 = new Object();
    v0.x = 1;
    return v0.x();
}
try {
    f0();
} catch (e) {
    WScript.Echo('PASS');
}
