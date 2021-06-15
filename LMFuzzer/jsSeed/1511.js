function f0(b, value) {
    b[1] = value;
}
function f1() {
    var v0 = [
        1.5,
        0,
        0
    ];
    f0(1.5);
    f0(v0);
}
f1();
