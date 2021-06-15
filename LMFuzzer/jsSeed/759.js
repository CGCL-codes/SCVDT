function f0(a) {
    return new String(a);
}
var v0;
for (var v1 = 0; v1 < 1000000; ++v1)
    v0 = f0('hello');
if (v0 != 'hello')
    throw new 'Error: bad result: '() + v0;
