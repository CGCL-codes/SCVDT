let v0 = function AsmModule(stdlib) {
    'use asm';
    function f0() {
    }
    function f1() {
        return f0() | 0;
    }
    return { empty: f0 };
}({});
print(v0.empty());
