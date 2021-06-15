try {
    throw '0';
} catch (e) {
    e === '0' ? print('Pass') : print('Fail');
}
