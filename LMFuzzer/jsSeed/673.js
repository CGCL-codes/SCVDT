function f0(actual, expected) {
    if (actual !== expected)
        throw new Error(`bad value: ${ String(actual) }`);
}
var v0 = () => /Cocoa/;
f0(v0.toString(), `() => /Cocoa/`);
