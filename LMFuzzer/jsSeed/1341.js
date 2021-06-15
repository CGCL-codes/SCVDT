function f0() {
    const v0 = 1;
    v0;
    WScript.Echo('PASSED');
}
function f1() {
    f0();
    f0();
    f0();
    f0;
}
WScript.Attach(f1);
