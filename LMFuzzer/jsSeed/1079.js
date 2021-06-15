delete Date.prototype[Symbol.toPrimitive];
let v0 = new Date();
if (typeof (v0 + 1) !== 'number')
    throw 'symbol was not deleted';
