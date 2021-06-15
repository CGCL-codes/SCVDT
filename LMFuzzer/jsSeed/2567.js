var v0, v1;
function f0(x) {
    var v2 = x++;
    return [
        x,
        v2
    ];
}
function f1() {
    for (var v3 = 0; v3 < 20; v3++) {
        [v0, v1] = f0('10');
    }
}
f1();
