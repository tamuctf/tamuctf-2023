# StorBox

Author: `kit`

Some hackers leaked out a few locations of the same coffee shop line for a meet up. We have sent agents out to all three of these locations but there was no luck finding them. Where else could they be meeting up?

Location 1: 1462 N Beauregard St B
Location 2: 801 N Glebe Rd
Location 3: 2925 S Glebe Rd

Flag format will be the street address with spaces replaced with underscores, for example: `gigem{200_Discovery_Dr}`

## Solution

I made a Google Earth project and pinned each of the three locations which formed a triangle. Searching "Starbucks" shows one location in the center of the triangle. The address of that Starbucks is the flag.

flag:
`gigem{950_S_George_Mason_Dr}`
