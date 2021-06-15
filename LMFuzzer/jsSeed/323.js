function f0(v0) {
    return arguments;
}
var v0 = f0(1, 2, 3);
delete v0[1];
Array.prototype.sort.apply(v0);
v0[10000000] = 4;
Array.prototype.sort.apply(v0);
