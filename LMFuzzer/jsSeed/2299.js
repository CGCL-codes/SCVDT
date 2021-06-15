function f0() {
    for (var v0 in c) {
        addPropertyName(v0);
    }
}
try {
    f0();
} catch (ex) {
    var v1 = ex.stack.replace(/\(.*\\/g, '(');
    WScript.Echo(v1);
}
