function f0() {
    {
        let v0 = arguments;
        return function () {
            return v0;
        };
    }
}
f0()();
