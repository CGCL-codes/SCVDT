function f0() {
    return eval('super.base()');
}
try {
    f0();
} catch (e) {
    WScript.Echo(e);
}
