function f0() {
    return function (parts) {
        return Object.isFrozen(parts) && Object.isFrozen(parts.raw);
    }`foo${ 0 }bar${ 0 }baz`;
}
if (!f0())
    throw new Error('Test failed');
