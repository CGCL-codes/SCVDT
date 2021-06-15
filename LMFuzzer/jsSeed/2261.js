var v0 = [
    'b',
    'a'
];
Array.prototype.unshift.call(v0, 'c');
if (v0.toString() != 'c,b,a')
    throw 'Error: bad result: ' + describe(v0);
