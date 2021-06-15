if (Object.prototype.toString.call(Array.prototype) !== '[object Array]') {
    $ERROR('The Array prototype object is itself an array; its' + '[[Class]] is "Array".');
}
