function f0() {
    var v0 = function () {
        return 'simple_escape';
    };
    return v0;
}
WScript.Echo(f0()());
WScript.Echo(f0()());
