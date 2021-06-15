var v0 = 0;
function f0() {
    print('pass');
    if (++v0 < 65) {
        WScript.SetTimeout(f0, 1000);
    }
}
WScript.SetTimeout(f0, 1000);
