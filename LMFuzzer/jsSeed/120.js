function f0() {
    return /[\uD800\uDC00\uFFFF]/.test('\uFFFF');
}
if (f0()) {
    WScript.Echo('Pass');
}
