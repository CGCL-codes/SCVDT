function f0(o) {
    if (!o)
        for (;;);
}
function f1(a) {
}
function f2() {
    f1(f0({}));
}
;
f2();
f2();
print('pass');
