# Courier

Author: `Addison`

Special delivery! This device emulates a delivery system, but we don't have the ability to connect to the stamping
device. Can you trick the target into leaking the flag?

Connections to `TODO` will connect you to the UART of the device. You can test with the provided files (just
install Rust with the `thumbv7m-none-eabi` target). We've provided the `sender/` implementation as a reference.

Hint: There are very few comments. The ones that are present are extremely relevant to the intended solution.

## Dev Notes

Contestants are provided with the courier.tar.gz (`make dist`) as well as connection details. You can test locally with
`make run` and connect to port 42069 on localhost.

Hints: (avoid using these if possible; if necessary, view in order and let me know which are viewed)

<details>

<summary>Hint 1</summary>

Don't worry too much about the UART implementation. It's mostly sane. Look at the implementation details of courier,
consignee, and courier-proto instead.

</details>

<details>

<summary>Hint 2</summary>

What's strange about courier-proto's `try_read_msg`? What happens to the input stream when an error occurs?

</details>

## Solution

See `solution` for details.

Flag: `gigem{what_is_old_becomes_new_again}`