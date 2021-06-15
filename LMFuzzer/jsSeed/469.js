function f0(x, f) {
    WScript.Echo(f());
}
function f1(param) {
    var v0 = function () {
        return param;
    };
    f0(1, v0);
}
f1('test1');
f1('test2');
