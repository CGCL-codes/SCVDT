function f0() {
    WScript.Echo('outer');
    function f1() {
        return f1;
    }
    if (v0)
        return f1();
    v0++;
}
var v0 = 0;
f0();
f0();
var v1 = f0();
WScript.Echo(typeof v1());
