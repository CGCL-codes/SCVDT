function f0(s) {
    f0(s.replace(/\s/g, ''));
}
try {
    f0('No');
} catch (e) {
}
