function f0(thing, buggy) {
    try {
        new thing();
    } catch (e) {
    }
}
var v0 = Function.prototype.bind();
f0(v0, true);
var v1 = Math.sin.bind();
f0(v1, true);
