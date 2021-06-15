function f0(x, v0) {
    with ('abcdefghijxxxxxxxxxx')
        var v0 = {};
}
function f1() {
    f0.apply(this, arguments);
}
for (var v1 = 0; v1 < 150000; v1++) {
    f1(v1);
}
