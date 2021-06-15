function f0() {
    function f1() {
        (function f() {
            eval('');
        }());
    }
    f1();
}
f0();
WScript.Echo('passed');
