function f0() {
    this.passed = 'x';
}
v0 = 'pass';
for (var v1 = 0; v1 < 100; v1++)
    new f0(v0);
function f1(value) {
}
f1.prototype = new f0();
