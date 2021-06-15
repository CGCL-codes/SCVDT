function f0(a, i) {
    a[i] = 'blah';
}
function f1(proto) {
    var v0 = Object.create(proto);
    v0[0] = 0;
    f0(v0, 0);
    f0(v0, 1);
    WScript.Echo(v0[1]);
}
