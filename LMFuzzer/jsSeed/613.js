Array.prototype.myfunc = function () {
};
Array.prototype[10] = 42;
Array.prototype.length = 3000;
var v0 = { name: 'n1' };
try {
    v0 = Object.freeze(v0);
} catch (e) {
    assertUnreachable();
}
