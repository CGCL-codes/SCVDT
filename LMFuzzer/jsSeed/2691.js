function f0(v0) {
    return { __proto__: v0 };
}
var v0 = {};
var v1 = f0(v0);
v0.x = 0.6;
Object.defineProperty(v0, 'x', { writable: false });
