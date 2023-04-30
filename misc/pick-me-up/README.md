# Pick Me Up

Author: `bit`

You're supposed to pick your friend up at the airport, but she didn't send you any information! When does this flight actually arrive and where should you pick her up? This screenshot was taken on 4/20. 

The flag format is `gigem{HH:MM-Gate}` in CDT with HH being hour **in 24 hour time** and MM for the minutes. Gate represents the gate that the plane arrives at. For example, if you were picking your friend up at 4:20 PM CDT at gate A1 would yield the flag `gigem{16:20-A1}`.

## Solution

Translating the messages in the screenshot reveals that the passenger is flying out of Taipei to IAH. I used the Houston airport website to search for this flight. 

<https://www.airport-houston.com/>

As listed in the flight record on the website, the flight landed at 12:28 at gate D7.

<https://www.airport-houston.com/iah-flight-arrival/BR52>

flag:
`gigem{00:28-D7}`
