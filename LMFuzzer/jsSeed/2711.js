function f0() {
    for (var v0 = 3; v0 < v1.length; v0++) {
        v1[v0] = v1[v0];
    }
}
var v1 = Array(10).fill(0);
f0();
v1.length = 100;
v1.push(v1.shift());
f0();
f0();
print(v1);
