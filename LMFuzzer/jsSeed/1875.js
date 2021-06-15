function f0() {
    var v0 = Object.getOwnPropertyDescriptor(Set, Symbol.species);
    return 'get' in v0 && Set[Symbol.species] === Set;
}
if (!f0())
    throw new Error('Test failed');
