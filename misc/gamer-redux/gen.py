import qrcode 
from pathlib import Path

flag = "gigem{cr33p3r_4w_m4444n}"

def gen_grid(msg):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=1,
        border=1,
    )
    qr.add_data(msg)
    qr.make()
    return qr.get_matrix()

grid = gen_grid(flag)
n = len(grid)

coords = []
for y in range(n):
    for x in range(n):
        if grid[y][x]:
            coords.append((x, y))


start_x = 1
start_z = 1
start_y = -3

inits = []
inits.append(f"fill ~{start_x} ~{start_y} ~{start_z} ~{n - 1 + start_x} ~40 ~{n - 1 + start_z} air")
inits.append(f"fill ~{start_x} ~{start_y} ~{start_z} ~{n - 1 + start_x} ~{start_y} ~{n - 1 + start_z} white_wool")
for (x, z) in coords:
    x += start_x
    z += start_z
    inits.append(f"summon armor_stand ~{x} ~{start_y} ~{z} {{NoGravity:1,Invisible:1}}")

inits.append('tellraw @a {"text":"Try walking on the wool, and see if you find anything interesting!"}')
repeats = [
    "execute at @a at @e[type=armor_stand,distance=..5] run setblock ~ ~ ~ black_wool",
    "execute at @a at @e[type=armor_stand,distance=6..50] run setblock ~ ~ ~ white_wool"
]

for i, rep in enumerate(repeats):
    inits.append(f'setblock ~ ~-5 ~{-i}' + ' repeating_command_block{Command:"' + rep + '",auto:1}')

inits.insert(0, "gamerule commandBlockOutput false")
inits.append('setblock ~ ~1 ~ command_block{auto:1,Command:"fill ~ ~ ~ ~ ~-3 ~ air"}')
inits.append("kill @e[type=command_block_minecart,distance=..1]")

payload = ",".join(f"{{id:command_block_minecart,Command:'{i}'}}" for i in inits)
final = "summon falling_block ~ ~.5 ~ {Time:1,BlockState:{Name:redstone_block},Passengers:[{id:armor_stand,Health:0,Passengers:[{id:falling_block,Time:1,BlockState:{Name:activator_rail},Passengers:[" + payload + "]}]}]}"

Path("sus.txt").write_text(final)

