function f0() {
    var v0 = Object.getOwnPropertyDescriptor(RegExp, Symbol.species);
    return 'get' in v0 && RegExp[Symbol.species] === RegExp;
}
if (!f0())
    throw new Error('Test failed');
