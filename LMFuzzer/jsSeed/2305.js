Object.defineProperty(Boolean.prototype, 'v', { set: constructor });
function f0(b) {
    b.v = 1;
}
f0(true);
f0(true);
f0(true);
