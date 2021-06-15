try {
    eval('{const x = 1;}WScript.Echo(x);');
} catch (e) {
    WScript.Echo(e);
}
try {
    eval('--foo 0');
} catch (e) {
    WScript.Echo(e);
}
