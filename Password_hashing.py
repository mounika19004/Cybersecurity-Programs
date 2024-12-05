#This program converts Password into into hash value using SHA-256
import hashlib

def Password_hashing(password):
  password_bytes=password.encode("utf-8") #encoding the password
  hash_object=hashlib.sha256(password_bytes)  #hashing using sha256
  hashed_password=hash_object.hexdigest()  #converting into hexadecimal value
  return hashed_password

password=input("Enter Password\n")
password_hash=Password_hashing(password)
print(f"The Hash value of entered password using SHA256 is: \"{password_hash}\" ")
