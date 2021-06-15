function f0() {
    f1();
}
function f1() {
    for (v8; 10; 0) {
    }
}
try {
    f0();
} catch (ex) {
}
try {
    f0();
} catch (ex) {
}
WScript.Echo('Passed');
