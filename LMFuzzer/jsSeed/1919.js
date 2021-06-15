function f0(v1) {
    var v0 = v1;
    v1 = function () {
        return v0;
    };
    return arguments[0];
}
WScript.Echo(f0('test1')());
WScript.Echo(f0('test2')());
