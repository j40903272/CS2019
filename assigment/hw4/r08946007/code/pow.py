from itertools import count
from hashlib import md5
msg = 'kaibro'
for i in count():
    hashid = md5((msg+str(i)).encode()).hexdigest()
    if hashid.startswith('3ad64'):
        print ((msg+str(i)).encode(),i,hashid)
        break