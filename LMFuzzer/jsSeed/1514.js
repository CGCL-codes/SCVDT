if (Object.prototype.toString.call('foo') !== '[object String]') {
    $ERROR('Let O be the result of calling ToObject passing the this ' + 'value as the argument.');
}
