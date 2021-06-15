function f0() {
}
function f1(x) {
    if (!x)
        throw 1;
    f0();
    return 'Passed';
}
function f2(x) {
    WScript.Echo(f1(x));
}
try {
    f2(0);
} catch (e) {
}
f2(1);
