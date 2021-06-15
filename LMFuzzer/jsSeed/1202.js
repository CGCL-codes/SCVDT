function f0(test, a) {
    var v0;
    if (test) {
        v0 = v0 | 0;
    }
    a[v0] = 1;
}
var v0 = new String();
f0(false, v0);
f0(false, v0);
v0 = new Int32Array(10);
f0(true, v0);
