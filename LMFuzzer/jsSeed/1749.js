function f0() {
    eval('delete x; const x = 32');
}
f0();
