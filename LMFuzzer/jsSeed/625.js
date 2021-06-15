function f0() {
    function f1(arguments) {
        eval('arguments');
    }
    f1('11');
    WScript.Echo('Pass');
}
WScript.Attach(f0);
