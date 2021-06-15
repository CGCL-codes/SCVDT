function f0(param, f1) {
    function f1() {
        return param;
    }
    return f1();
}
WScript.Echo(f0('test1'));
WScript.Echo(f0('test2'));
