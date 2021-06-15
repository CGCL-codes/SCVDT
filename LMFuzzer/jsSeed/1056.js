var v0 = 1;
function f0() {
    throw v0;
}
try {
    f0();
} catch (e) {
    WScript.Echo(e);
}
WScript.Echo(v0);
