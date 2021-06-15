v0 = 0;
function f0() {
}
function f1(x) {
    var v1 = 'inner';
    new f0(v0, { SECTION: ++v1 });
}
f1(1111);
