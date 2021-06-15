var v0;
var v1 = [
    'a',
    'b'
];
for (var v2 = 0; v2 < 10000000; ++v2)
    v0 = v1[v2 & 1] + 'c';
