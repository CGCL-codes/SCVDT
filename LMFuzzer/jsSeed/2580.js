function f0() {
    assertTypeErrorMessage(() => {
        ctypes.default_abi.toSource(1);
    }, 'ABI.prototype.toSource takes no arguments');
}
if (typeof ctypes === 'object')
    f0();
