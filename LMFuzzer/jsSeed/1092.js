function f0() {
    'use asm';
    function f1() {
        function f0() {
        }
        ;
    }
    return f1;
}
f0()();
