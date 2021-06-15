if (delete 1 !== true) {
    $ERROR('#1: delete 1 === true');
}
if (delete new Object() !== true) {
    $ERROR('#2: delete new Object() === true');
}
