Object.defineProperty(Number.prototype, 'v', { get: constructor });
function f0(b) {
    return b.v;
}
f0(2);
f0(3);
f0(4);
