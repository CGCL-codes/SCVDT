eval('function __funcA(__arg){return __arg;};');
if (typeof __funcA !== 'function') {
    $ERROR('#1: unicode symbols in function name are allowed');
}
