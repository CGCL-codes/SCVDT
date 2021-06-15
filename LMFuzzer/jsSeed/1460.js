var v0;
v0 = a => a || 'nothing';
assertEq(v0.length, 1);
assertEq(v0(0), 'nothing');
assertEq(v0(1), 1);
