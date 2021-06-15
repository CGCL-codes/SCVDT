f0();
f0();
function f0() {
    let v0 = 200;
    let v1 = 100;
    WScript.Echo('PASSED');
}
function f1() {
    f0();
    f0();
    f0();
    f0;
}
WScript.Attach(f1);
