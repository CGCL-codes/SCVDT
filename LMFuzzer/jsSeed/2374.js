function f0(v) {
    WScript.Echo(v + '');
}
var v0 = 10;
try {
    v0();
    f0('no exception');
} catch (e) {
    f0(e.message);
}
