v0 = {};
v1 = [].__proto__;
function f0(o) {
    o.f = v1;
}
for (let v2 = 0; v2 < 50; v2++) {
    f0(v0);
}
