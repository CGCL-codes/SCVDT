var v0 = Function('return this')();
if (typeof v0.count !== 'undefined')
    throw new Error(`bad value ${ v0.count }`);
v0.count = 1;
