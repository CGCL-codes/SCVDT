var v0 = 1;
function f0() {
    v0 = 2;
    let v1 = 2;
    let v2 = 2;
    v0 = 2;
}
f0();
v0 = 2;
v0 = 2;
v0 = 2;
function f1() {
    let v3 = 1;
    v0 = 2;
}
f1();
v0 = 2;
