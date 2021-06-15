function f0(x) {
    return function foo() {
        this.bar = foo;
        return x;
    }();
}
print(f0(42));
print(bar());
