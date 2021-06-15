function f0(value, exception) {
}
try {
    new f0(Math.LN2, ++INVALID_INTEGER_VALUE ? exception + 1.1 : 1900);
} catch (e) {
}
