function f0(actual, expected) {
    if (actual !== expected)
        throw new Error('bad value: ' + actual);
}
var v0 = Object.keys(/Cocoa/);
f0(JSON.stringify(v0.sort()), '[]');
