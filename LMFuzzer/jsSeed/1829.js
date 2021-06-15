var v0;
function f0(f) {
    v0 = f;
}
function f1(param) {
    f0(function () {
        return param;
    });
}
f1('test1');
WScript.Echo(v0());
f1('test2');
WScript.Echo(v0());
