function f0() {
    var v0 = Object.getOwnPropertyDescriptor(Promise, Symbol.species);
    return 'get' in v0 && Promise[Symbol.species] === Promise;
}
if (!f0())
    throw new Error('Test failed');
