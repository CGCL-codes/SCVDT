var v0 = 1;
with ({ a: 2 }) {
    v0++;
    v0 = 100;
    WScript.Echo(v0);
    WScript.Echo('PASSED');
}
WScript.Echo(v0);
