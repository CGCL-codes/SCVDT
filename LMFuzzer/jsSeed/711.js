if ('$$abcdabcd'.indexOf('ab', eval('"-99"')) !== 2) {
    $ERROR('#1: "$$abcdabcd".indexOf("ab",eval("\\"-99\\""))===2. Actual: ' + '$$abcdabcd'.indexOf('ab', eval('"-99"')));
}
