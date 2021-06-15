function f0() {
    try {
        throw 'bar';
    } finally {
        return 'baz';
    }
}
f0();
print({});
