v0 = [];
for (var v1 = 0; v1 < 1000; v1++) {
    v0[v1] = v1;
}
function f0(x) {
    for (var v1 in x) {
    }
}
if (typeof schedulegc != 'undefined')
    schedulegc(100);
f0(v0);
