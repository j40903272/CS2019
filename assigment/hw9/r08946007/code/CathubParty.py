import requests
import base64
import urllib.parse
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

cookie_dict = {"session":"d40b20d4-0860-4093-aace-46d5d9296536", 
               "rack.session":"BAh7CEkiD3Nlc3Npb25faWQGOgZFVEkiRTJhYmZjZTYyYzFmYzcwZjI5ZGEw%0AMzE5YjNhNTM2ZDM5MjgyMGYyMDdmMmQ1NDA3NzYzZTEyZDgwOTVmODJhY2EG%0AOwBGSSIKZmxhc2gGOwBGewBJIgx1c2VyX2lkBjsARmkO%0A--795ccbd253867a941abeb2bdfa7759d5b7eeb591", 
               "PHPSESSID":"f7dbfk3rsds589hcggv39pabl6",
               "FLAG":"CZ5y3p9fcBjBbDJdBqyDc7pdcgubVVZwco%2FNLiDW1jNdfl5eNxKqFEcN8GtbYcVZ4ReGFuyW%2B3wWV1jk00kl6qVpaCTWvbtV60rtl5tcqUIPo%2FPuHVfq%2Bq6T%2BLKvAvFk"}


def send(flag):
    flag = str(base64.b64encode(flag), encoding = 'utf-8')
    flag = urllib.parse.quote(flag)
    cookie_dict["FLAG"] = flag
    with requests.Session() as s:
        r = s.get('https://edu-ctf.csie.org:10190/party.php', cookies=cookie_dict, verify=False)
    return r


def solve():
	FLAG = []
	flag = base64.b64decode(urllib.parse.unquote(cookie_dict["FLAG"]))
	length = len(flag) // 16
	block = [flag[i*16:(i+1)*16] for i in range(length)]

	for i in range(length-1):
	    prefix = b''.join([block[j] for j in range(length-2-i)])
	    suffix = block[length-1-i]
	    current = list(block[length-2-i][:16])

	    for j in range(15, -1, -1):
			# make cypher to decode as correct padding
	        for k in range(j+1, 16):
	            current[k] ^= ((16-j) ^ (15-j))
	        
	        for k in range(1, 256):
	            tmp = current.copy()
	            tmp[j] = tmp[j] ^ k
	            tmp = bytes(tmp)

	            message = prefix + tmp + suffix
	            res = send(message)
	            
	            if b'Your flag seems strange @@' in res.content:
	                FLAG.append(k^(16-j))
	                current[j] ^= k
	                break
	        # when cypher is equals to padding
	        if len(FLAG) != (i*16)+(16-j):
	            FLAG.append(16-j)

	print("".join([chr(j) for j in FLAG][::-1]).strip())



solve()