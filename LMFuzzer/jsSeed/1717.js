var v0 = [
    ,
    ,
    ,
];
try {
    Array.prototype[1] = 'prototype';
    v0.reduce(function () {
    });
} finally {
    delete Array.prototype[1];
}
