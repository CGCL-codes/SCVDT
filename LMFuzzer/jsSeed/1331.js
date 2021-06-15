var v0 = 100;
function f0() {
    v0--;
    return v0;
}
for (var v1 = 0; v1 < 10; ++v1) {
    var v2 = v1;
    while (f0() > 0 && v2 > 5) {
        WScript.Echo('f: ' + v0);
        --v2;
    }
}
