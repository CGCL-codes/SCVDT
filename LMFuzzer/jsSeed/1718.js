Number.NaN = 1;
if (Number.NaN === 1) {
    $ERROR('#1: Globally defined variable NaN has not been altered by program execution');
}
