function f0() {
    var v0 = 1;
    {
        let v0 = 2;
        v0;
    }
    v0;
    WScript.Echo('PASSED');
}
var v1 = f0;
WScript.Attach(v1);
WScript.Detach(v1);
WScript.Attach(v1);
