if (!function () {
        return function () {
            return typeof this;
        }() === 'undefined' && typeof this === 'undefined';
    }()) {
    throw '\'this\' had incorrect value!';
}
