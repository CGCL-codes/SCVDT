Array.prototype[1] = 100;
function f0(param) {
    var v0 = new Array(1, param, 3);
    return v0;
}
WScript.Echo(f0(undefined)[1]);
WScript.Echo(f0(undefined)[1]);
