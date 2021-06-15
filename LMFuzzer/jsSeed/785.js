function f0() {
    var v0 = Object.getOwnPropertyDescriptor(Map, Symbol.species);
    return 'get' in v0 && Map[Symbol.species] === Map;
}
if (!f0())
    throw new Error('Test failed');
