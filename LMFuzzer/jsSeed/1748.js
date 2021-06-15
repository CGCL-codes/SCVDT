if (delete x !== true) {
    $ERROR('#1: delete x === true');
}
if (delete this.x !== true) {
    $ERROR('#2: delete this.x === true');
}
