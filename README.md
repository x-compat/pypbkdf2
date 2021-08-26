## PBKDF2 implementation for Python

PBKDF2 (Password-Based Key Derivation Function 2) https://en.wikipedia.org/wiki/PBKDF2

# USAGE

## Install

TODO
```
pip install ****
```


- **Hash a Password**
```python
import pypbkdf2

p = pypbkdf2.PyPBKDF2(salt_size=20)
res = p.hash_password('12345')
cipher_text = res[0]
salt = res[1]

# save this two into your Database
print(cipher_text)
print(salt)
```

- **Verify a Password**
```python
import pypbkdf2

p = pypbkdf2.PyPBKDF2(salt_size=20)
res = p.hash_password('12345')
cipher_text = res[0]
salt = res[1]

valid = p.verify_password('12345', cipher_text, salt)

print(valid) # True
```

# Doc
 TODO
	
	
## x-compat 2021