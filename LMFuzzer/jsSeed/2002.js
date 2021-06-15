var v0 = new Float32Array(10);
v0[0] = 5;
var v1 = 0;
do {
    v0[v1 + 1] = v0[v1] - 1;
    v1 += 1;
} while (v0[v1]);
