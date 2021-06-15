if (!{} !== false) {
    $ERROR('#1: !({}) === false');
}
if (!function () {
        return 1;
    } !== false) {
    $ERROR('#2: !(function(){return 1}) === false');
}
