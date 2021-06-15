function f0(a) {
    a[a.length] = 1;
}
function f1(a, i, v) {
    a[i] = v;
}
f0([]);
v0 = {};
f1(v0);
v0 = {};
f0(v0);
