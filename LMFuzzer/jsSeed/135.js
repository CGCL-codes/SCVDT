var v0 = 0;
while (v0++ < 5) {
    if (v0 == 3) {
        WScript.RequestAsyncBreak();
    }
}
function f0() {
    var v1 = 1;
    v1 = 2;
}
f0();
WScript.Echo('pass');
