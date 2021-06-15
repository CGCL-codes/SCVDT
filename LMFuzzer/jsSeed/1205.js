function f0() {
    class C {
    }
    var v0 = C;
    {
        class C {
        }
        var v1 = C;
    }
    return C === v0;
}
if (!f0())
    throw new Error('Test failed');
