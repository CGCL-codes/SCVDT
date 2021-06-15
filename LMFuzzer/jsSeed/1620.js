function f0() {
    throw 'PASS';
}
function f1() {
    try {
        while (true) {
            f0();
        }
    } catch (e) {
        WScript.Echo(e);
    }
}
f1();
