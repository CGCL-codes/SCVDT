function f0(a, i) {
    return a[i];
}
function f1() {
    return f0(new Proxy({}, {}), undefined);
}
f1();
f1();
f0([
    11,
    22,
    33
], 0);
f1();
