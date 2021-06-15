function f0(v0) {
    v0[0]();
}
var v0 = new Uint32Array(1);
try {
    f0(v0);
} catch (ex) {
}
try {
    f0(v0);
} catch (ex) {
    WScript.Echo(ex.message);
}
