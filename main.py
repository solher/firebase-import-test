from __future__ import print_function
import base64
import sys
import time
import firebase_admin
import random
import string
from firebase_admin import credentials
from firebase_admin import auth
from firebase_admin import exceptions
from firebase_admin import tenant_mgt
from multiprocessing import Pool
from multiprocessing import freeze_support


firebase_admin.initialize_app(credentials.Certificate("./service-account.json"))


def run_multiprocessing(func, i, n_processors):
    with Pool(processes=n_processors) as pool:
        return pool.map(func, i)

def rand_string(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def import_with_bcrypt(n):
	users = []
	for x in range(1, 1000):
		uid = rand_string(8)

		users.append(auth.ImportUserRecord(
            uid=uid,
            provider_data=[ # user with Google provider
                auth.UserProvider(
                    uid=uid,
                    provider_id='google.com'
                )
            ],
        ))

	hash_alg = auth.UserImportHash.bcrypt()

	print('importing ' + str(n))

	try:
		start = time.time()
		result = auth.import_users(users, hash_alg=hash_alg)
		print('imported ' + str(n) + ' time: {}s\n'.format((time.time()-start)))
		for err in result.errors:
		    print('Failed to import user:', err.reason)
	except exceptions.FirebaseError as error:
		print('Error importing users:', error)

def main():
    start = time.time()
    num_max = 10000
    n_processors = 32
    x_ls = list(range(num_max))
    out = run_multiprocessing(import_with_bcrypt, x_ls, n_processors)

    print("Input length: {}".format(len(x_ls)))
    print("Output length: {}".format(len(out)))
    print("Mutiprocessing time: {}mins\n".format((time.time()-start)/60))



if __name__ == "__main__":
    freeze_support()
    main()
