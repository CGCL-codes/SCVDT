function f0() {
    function f1() {
        return x => new.target;
    }
    return new f1()() === f1 && f1()() === undefined;
}
if (!f0())
    throw new Error('Test failed');
