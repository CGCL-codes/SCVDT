var v0 = 0;
function f0() {
    for (var v1 = 0; v1 < 2; v1++) {
        v0 = v0 + 1;
    }
    this.eval('function x() {};');
    delete this['x'];
}
f0();
f0();
