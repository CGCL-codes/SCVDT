var v0 = 0;
function f0() {
    var v1 = new Function('return ' + v0++);
    v1();
}
WScript.Attach(f0);
WScript.Detach(f0);
WScript.Echo('pass');
