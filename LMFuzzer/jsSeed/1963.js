var v0 = 'ሴ-------';
for (var v1 = 0; v1 < 17; v1++) {
    v0 += v0;
}
v0.replace(/[\u1234]/g, '');
