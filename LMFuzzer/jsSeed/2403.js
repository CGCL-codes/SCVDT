function f0(t) {
}
function f1(t) {
    var v0 = (f0(t) + 4) % 7;
    return v0 < 0 ? 7 + v0 : v0;
}
var v1 = 'No Error';
for (var v2 = 0; v2 < 50; v2++) {
    var [] = [v1 ? f1(v2.a) : true], v3;
}
