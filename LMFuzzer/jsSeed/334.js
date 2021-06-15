function f0() {
    var v0 = Intl.Collator();
    var v1 = Intl.NumberFormat();
    var v2 = Intl.DateTimeFormat();
    WScript.Echo('PASSED');
}
var v3;
WScript.Attach(f0);
WScript.Detach(f0);
