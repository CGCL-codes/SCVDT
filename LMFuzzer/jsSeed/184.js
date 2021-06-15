var v0 = 1;
with ({ a: 2 }) {
    v0++;
    eval('a=100;');
    WScript.Echo(v0);
    WScript.Echo('PASSED');
}
WScript.Echo(v0);
