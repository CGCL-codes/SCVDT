function f0() {
    with ({ x: 1 % {} }) {
        for (var v0 = 0; v0 < 1; v0++) {
            x;
        }
    }
}
f0();
f0();
WScript.Echo('PASS');
