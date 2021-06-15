function f0() {
}
function f1() {
    var v0 = 'HELLO';
    var v1 = 'test';
    var v2 = v0 + v1;
}
WScript.Attach(f1);
WScript.Detach(f1);
WScript.Echo('PASSED');
