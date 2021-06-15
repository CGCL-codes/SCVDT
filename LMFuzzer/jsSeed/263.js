var v0 = false;
function f0(i) {
    var v1 = i + 1;
    var v2 = v1;
    if (v0) {
        return v2;
    }
    return 1;
}
WScript.Echo(f0(10));
v0 = true;
WScript.Echo(f0(10));
