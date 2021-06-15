function f0(items, n) {
    for (var v0 = 0; v0 < 10; v0++)
        arguments[2](items, this);
}
function f1() {
    print(this);
}
f0('crab', 'crab', f1);
