function f0() {
    var v0 = Object.getOwnPropertyDescriptor(Array, Symbol.species);
    return 'get' in v0 && Array[Symbol.species] === Array;
}
if (!f0())
    throw new Error('Test failed');
