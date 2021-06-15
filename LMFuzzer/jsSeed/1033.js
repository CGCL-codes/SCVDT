function f0(i) {
    var v0 = 3;
    var v1;
    if (i) {
        v0 = 4;
        v1 = v0 + i;
    } else {
        v1 = v0 + i;
    }
    return v1;
}
WScript.Echo(f0(true));
WScript.Echo(f0(false));
