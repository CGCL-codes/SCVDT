function f0(f) {
    return f.call.apply(f.bind, arguments);
}
function f1(a, b) {
}
for (var v0 = 0; v0 < 20; ++v0) {
    f1.call(undefined, {}, f0(function () {
    }));
}
