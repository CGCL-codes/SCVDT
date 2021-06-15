Object.defineProperty(Number.prototype, 'v', { set: constructor });
function f0(b) {
    b.v = 1;
}
f0(2);
f0(3);
f0(4);
