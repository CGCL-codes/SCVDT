var v0 = 'a';
for (var v1 = 0; v1 < 12; v1++)
    v0 += v0;
v0 = v0 + 'b' + v0;
v0.replace(/b/, 'a');
