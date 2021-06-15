function f0() {
    function f1() {
        eval('');
    }
    let v0 = 10;
    const v1 = 20;
}
f0.apply({});
WScript.Echo('PASSED');
