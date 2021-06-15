var v0 = 0;
function f0() {
    return this;
}
function f1() {
    v0 += 1;
    if (v0 === 2)
        throw new f0();
}
f1();
