function f0() {
    var v0 = 0;
    let v1 = 1;
    const v2 = 2;
    v0;
    function f1() {
        v1;
        v2;
    }
    f1();
}
f0();
WScript.Echo('PASSED');
