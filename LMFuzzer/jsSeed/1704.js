function f0() {
    var v0 = 1;
    {
        v0;
        function f1() {
        }
        f1();
        v0;
    }
    v0;
}
f0();
WScript.Echo('PASSED');
