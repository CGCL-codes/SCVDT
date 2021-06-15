if (Object.prototype.toString.call(true) !== '[object Boolean]') {
    $ERROR('Let O be the result of calling ToObject passing the this ' + 'value as the argument.');
}
