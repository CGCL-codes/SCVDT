function f0() {
    return typeof ArrayBuffer[Symbol.species] === 'function';
}
if (!f0())
    throw new Error('Test failed');
