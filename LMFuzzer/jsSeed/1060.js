var v0 = { x: 0 };
delete v0.x;
function f0(v0, p, v) {
    v0[p] = v;
}
f0(v0, 'x', 1);
f0(v0, 'x', 1);
f0(v0, '0', 1);
