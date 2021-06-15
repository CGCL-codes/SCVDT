function f0() {
    var v0 = Symbol.for('foo');
    return Symbol.for('foo') === v0 && Symbol.keyFor(v0) === 'foo';
}
if (!f0())
    throw new Error('Test failed');
