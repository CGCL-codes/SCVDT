function f0(code) {
    eval(code);
}
f0('    function h({x}) {        print(x)    }    h(/x/);');
