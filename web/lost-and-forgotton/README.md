# Lost and Forgotten

Author: `Mr. Blade`

## Description

I seem to have forgotten the password to my most recent writeup. I wonder if there is any way to recover it.

## Dev notes

Start challenge: `make run`

Stop challenge: `make stop`

Message me if there is not enough information in the description I can add more to lower the difficulty if needed.

## Writeup
After some messing around with things, it seems like the 2 things we can interact with are entering a secret code or using a search function, which appears to actually do some searching based on matching substring.

This search probably has a database behind it, so let's test for SQL injection. Trying the following payload returns all of the writeups:

```
' #
```

So there is a vuln here, next is to do some enumeration. I need to know how many columns it is pulling, so I tried union select with more columns until this returned all the writeups plus a new entry

```
' UNION SELECT 1, 2, 3, 4, 5, 6#
```

Next, let's see what tables there are. Running the following:
```
' UNION SELECT Table_name, 2, 3, 4, 5, 6 from information_schema.tables#
```

Dumps a bunch of stuff, but one of the interesting table names is articles, which likely contains all of the writeups we are seeing. Let's see what columns there are:
```
' UNION SELECT column_name, 2, 3, 4, 5, 6 from information_schema.columns#
```

This query shows that there is a column called access_code. Let's query for that column from the articles table with
```
' UNION SELECT access_code, 2, 3, 4, 5, 6 from articles#
```

This gets us a code `ba65ba9416d8e53c5d02006b2962d27e`. Putting this in as the secret code gets us the flag:

`tamuctf{st4te_0f_th3_UNION_1njecti0n}`
