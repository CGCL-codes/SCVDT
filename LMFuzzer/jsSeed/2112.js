function f0(x, x) {
    return x == 2;
}
if (f0(1, 2))
    WScript.Echo('Passed\n');
else
    WScript.Echo('FAILED\n');
