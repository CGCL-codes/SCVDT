var v0 = new Error('ErrorMessage');
v0.name = '';
assert.sameValue(v0.toString(), 'ErrorMessage', 'errObj.toString()');
