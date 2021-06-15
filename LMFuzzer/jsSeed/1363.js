function f0() {
    var v0 = new Intl.Collator();
    v0.compare('a', 'b');
    WScript.Echo('PASSED');
}
WScript.Attach(f0);
