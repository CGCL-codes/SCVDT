function f0(a) {
    return 'foo' + new String(a);
}
var v0;
for (var v1 = 0; v1 < 100000; ++v1)
    v0 = f0('hello');
if (v0 != 'foohello')
    throw 'Error: bad result: ' + v0;
