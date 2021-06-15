function f0() {
    try {
        throw 'foo';
        return 7;
    } finally {
        return 42;
    }
}
var v0 = f0();
if (v0 != 42)
    print('Wrong result: ' + v0);
