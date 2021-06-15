if (function __func() {
        return 0;
    }) {
    ;
} else {
    $ERROR('#1: Function expession inside the "if" expression is allowed');
}
