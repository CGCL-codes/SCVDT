function f0(code) {
    var v0 = new Function(code);
    try {
        v0();
    } catch (e) {
    }
}
f0('');
f0('');
f0('');
f0('this.function = 7;');
