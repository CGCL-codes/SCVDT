v0 = 123;
function f0() {
}
function f1(o) {
    v1 = v0.p;
    eval('o');
}
f1(f0);
