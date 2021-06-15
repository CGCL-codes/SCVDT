var v0 = [
    2.5,
    1.5
];
v0.length = 1000000000;
v0.length = 2;
Array.prototype.unshift.call(v0, 3.5);
if (v0.toString() != '3.5,2.5,1.5')
    throw 'Error: bad result: ' + describe(v0);
