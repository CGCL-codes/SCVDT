let v0 = 'function foo() {\n';
let v1 = 65536;
for (let v2 = 0; v2 < v1; v2++)
    v0 += 'let ns' + v2 + ' = ' + v2 + ';\n';
v0 += '};';
eval(v0);
