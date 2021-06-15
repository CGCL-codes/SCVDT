var v0 = {};
var v1;
function f0() {
    v1 = v0.a;
    WScript.Echo('v = ' + v0.a);
}
f0();
f0();
v0.a = 0;
f0();
