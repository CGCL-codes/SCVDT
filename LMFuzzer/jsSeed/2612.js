f0();
function f0() {
    print('Undefined throw test.');
    throw void 0;
    print('FAILED!: Should have exited with uncaught exception.');
}
