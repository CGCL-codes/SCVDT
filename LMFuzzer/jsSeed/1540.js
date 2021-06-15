Object.defineProperty(Boolean.prototype, 'v', { get: constructor });
function f0(b) {
    return b.v;
}
f0(true);
f0(true);
f0(true);
