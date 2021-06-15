function f0() {
    var v0 = {};
    Reflect.set(v0, 'quux', 654);
    return v0.quux === 654;
}
if (!f0())
    throw new Error('Test failed');
