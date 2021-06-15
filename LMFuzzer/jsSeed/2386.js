function f0(x) {
    'use asm';
    return !(1 || x);
}
for (var v0 = 0; v0 < 1; v0++) {
    (function (x) {
        +f0(+x);
    }());
}
