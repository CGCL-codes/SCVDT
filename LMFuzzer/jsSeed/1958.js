var v0 = ' ';
for (var v1 = 0; v1 < 22; v1++) {
    v0 = v0 + v0;
}
v0 += 'var a = 1 + 1;';
eval(v0);
