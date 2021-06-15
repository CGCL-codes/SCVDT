function f0() {
    function f1() {
        (function f() {
        }());
    }
    f1();
}
f0();
WScript.Echo('passed');
