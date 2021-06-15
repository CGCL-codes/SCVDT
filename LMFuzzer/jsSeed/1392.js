function f0() {
    assertTypeErrorMessage(() => {
        ctypes.PointerType({});
    }, 'argument of PointerType must be a CType');
}
if (typeof ctypes === 'object')
    f0();
