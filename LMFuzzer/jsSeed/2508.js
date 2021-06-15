function f0() {
    var v0 = 1;
    function f1() {
        v1 = 1;
    }
    for (var v2 = 0; v2 < 1 && f1.call(); v2++) {
        Math.sin();
    }
}
;
f0();
f0();
WScript.Echo('PASS');
