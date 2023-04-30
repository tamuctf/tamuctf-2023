# Discordance

Author: `SkrubLawd`

An admin was helping run a discord-hosted CTF and accidentally released a challenge that displayed the flag, but they were able to take it down before anyone could get it. The new challenge is way too hard and no one can solve it. All we have is the admin's discord data. Can you get the flag from the originally leaked challenge?

## Solution
Looking through the servers folder initially, I looked through index.json and noticed that there was a server named umatCTF, a parody of our very own TAMUctf. Briefly looking through the folders for each server did not really provide any additional information. 

I looked through the messages folder and noted that the structure of the folder is organized by `cCHANNEL_ID` and within it, a `channel.json` describing the channel information and a `messages.csv`. I ran `awk -F "," '{print $3}' */*.csv` and `awk -F "," '{print $4}' */*.csv` to parse the csvs and look at all the files at once. I noticed some mentions about a challenge in base64 as well as an image challenge here. 

Though, to narrow down my search I used the command `grep -ri umatctf .` to find all the channels in the umatctf server and simply deleted all the other channels. 

In these narrowed down channels: 
- I found one that was named challenges with the id 1096175436750389400, likely where the challenge information were uploaded. 
- I ran the parsing command again and noted that a message with the id 1098484588457771049 which involved an image had an error.
- Also, there was the mention of a yep_cool_name as the file name of the image.

I noticed that I now had all the information in a discord media cdn link and I pieced it together like so. 
https://cdn.discordapp.com/attachments/1096175436750389400/1098484588457771049/yep_cool_name.png

Looking at this image yields the flag `gigem{d15c0rd_k3ep5_d3l37ed_f1l3s?!?!}`
