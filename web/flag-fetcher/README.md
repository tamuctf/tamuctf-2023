# Flag Fetcher

Author: `Addison`

I wrote a program which demonstrates how ed25519 keys can be used to sign challenges, but
it's not working for some reason. Can you help me figure out what's wrong with my actix
server? I swear, I've tried everything. I got the routes right, my hosting works fine, but
for some reason, the sign endpoint just isn't working. Go on, give it a look. I've been
debugging this thing for hours but really I just can't find the solution. actix is so hard
to understand sometimes. I turned on debugging. I made sure my signing algo works fine.
But for whatever reason, I'm not getting any response back on that endpoint. It's so
frustrating. Why do people even do web anyways? What's the point? How am I supposed to
continue as a respected developer when I can't even make a basic webserver? Sometimes I
wonder if I should give up programming and go make a garden. That would be nice, don't you
think? Gardening sounds like a nice break from programming and security. Hell, I bet the
pay is comparable for some of those positions. Can you imagine gardening for a big company
or maybe a really wealthy person? Have one of those on-site housing sheds, like in that
Netflix series. What was it called? Oh, yeah, anyways, here's the code. Got it hosted in
a scratch container at the moment. I think it's so cool that you can do that with Rust.
Just compile it for musl and slam it in a container on its own. You know, I once tried to
do that with some C code, but the tools are just not there to get async handling working.
Go might be able to do it, but who uses that language anyways? Ah, sorry, yeah, it's
hosted at http://flag-fetcher.tamuctf.com/. Happy hunting.

Contestants are provided with Cargo.toml, src/main.rs, index.html, and static/runtime.js.
**Don't add the Dockerfile or the README.**

## Solution

LFI key because of vuln in `/static/`

`http://localhost:8080/static//key`

I used the leaked private key and the provided source files to spin up a working version, and used it to sign the challenge from the original server. Submitting the signed challenge provides the flag.

To fix the error in the server, the `/sign` route needs to be activated by adding `.service(sign)` to `HttpServer::new()`.

`gigem{the_root_of_all_evil_b8c3c530}`

