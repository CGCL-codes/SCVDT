function f0(param) {
    var v0;
    var v1;
    v0 = v1 = function () {
        return param;
    };
    return v0;
}
WScript.Echo(f0('test1')());
WScript.Echo(f0('test2')());
