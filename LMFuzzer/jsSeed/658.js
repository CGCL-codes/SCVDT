var v0 = [
    2,
    1
];
Array.prototype.unshift.call(v0, 3);
if (v0.toString() != '3,2,1')
    throw 'Error: bad result: ' + describe(v0);
