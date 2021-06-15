function f0() {
    var v0 = 3;
    var v1 = function () {
        WScript.Echo(v0);
    };
    return v1;
}
function f1(f) {
    f();
}
var v2 = f0();
f1(v2);
