# Blackbox

Author: `Mr. Blade`

## Description

I took a survey to find our dev's least favorite type of web challenge. The results of my survey showed that blackbox web is by far the most frustrating type of web challenge. Let's see what your opinion of it it.

## Solution

The challenge is much more difficult without the password being in the comments ;)

![](https://cdn.betterttv.net/emote/5d76c43abd340415e9f32fb1/3x)

\> be me<br>
\> robots.txt shows .git exists<br>
\> .git is forbidden :sadge:<br>
\> codebreakers task b2 enters my mind<br>
\> use git-dumper<br>
\> lmao the files exists (SOURCE!!!)<br>
\> read `util.py` and find `SECRET_KEY` is defined but not shown (h m m)<br>
\> index.php shows `require ./config.php`... ඞඞඞ<br>
\> can't traverse to config.php, use filter wrapper to pull the file in a different way (http://localhost:8000/?page=php://filter/convert.base64-encode/resource=config)<br>
\> decode file, get `SECRET_KEY`<br>
\> *back to website now*<br>
\> go to login page, grab `auth_token` cookie and decode to understand the format<br>
\> realize there's a `user_key` field... pain<br>
\> *back to .git directory*<br>
\> oh wow, a sqlite database<br>
\> grab the only entry in `users` and get the `user_key`<br>
\> reconstruct admin cookie<br>
\> replace the entries in the guest cookie with the admin values (`{"username":"admin","user_key":"26ceb685f46e6d22","admin":true}`) and base64 encode it<br>
\> we can also recreate the checksum with the `SECRET_KEY` according to `util.py`<br>
\> change `auth_token` on the website to the values we just created<br>
\> flag is so free: `tamuctf{my_f4v0rit4_7yp3_0f_w3b_ch4113ng3}`<br>
🅱️
