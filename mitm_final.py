import pandas as pd
# SDES

KeyLength = 10
SubKeyLength = 8
DataLength = 8
FLength = 4
 
# Tables for initial and final permutations (b1, b2, b3, ... b8)
IPtable = (2, 6, 3, 1, 4, 8, 5, 7)
FPtable = (4, 1, 3, 5, 7, 2, 8, 6)
 
# Tables for subkey generation (k1, k2, k3, ... k10)
P10table = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8table = (6, 3, 7, 4, 8, 5, 10, 9)
 
# Tables for the fk function
EPtable = (4, 1, 2, 3, 2, 3, 4, 1)
S0table = (1, 0, 3, 2, 3, 2, 1, 0, 0, 2, 1, 3, 3, 1, 3, 2)
S1table = (0, 1, 2, 3, 2, 0, 1, 3, 3, 0, 1, 0, 2, 1, 0, 3)
P4table = (2, 4, 3, 1)
 
def perm(inputByte, permTable):
    """Permute input byte according to permutation table"""
    outputByte = 0
    for index, elem in enumerate(permTable):
        if index >= elem:
            outputByte |= (inputByte & (128 >> (elem - 1))) >> (index - (elem - 1))
        else:
            outputByte |= (inputByte & (128 >> (elem - 1))) << ((elem - 1) - index)
    return outputByte
 
def ip(inputByte):
    """Perform the initial permutation on data"""
    return perm(inputByte, IPtable)
 
def fp(inputByte):
    """Perform the final permutation on data"""
    return perm(inputByte, FPtable)
 
def swapNibbles(inputByte):
    """Swap the two nibbles of data"""
    return (inputByte << 4 | inputByte >> 4) & 0xff
 
def keyGen(key):
    """Generate the two required subkeys"""
    def leftShift(keyBitList):
        """Perform a circular left shift on the first and second five bits"""
        shiftedKey = [None] * KeyLength
        shiftedKey[0:9] = keyBitList[1:10]
        shiftedKey[4] = keyBitList[0]
        shiftedKey[9] = keyBitList[5]
        return shiftedKey
 
    # Converts input key (integer) into a list of binary digits
    keyList = [(key & 1 << i) >> i for i in reversed(range(KeyLength))]
    permKeyList = [None] * KeyLength
    for index, elem in enumerate(P10table):
        permKeyList[index] = keyList[elem - 1]
    shiftedOnceKey = leftShift(permKeyList)
    shiftedTwiceKey = leftShift(leftShift(shiftedOnceKey))
    subKey1 = subKey2 = 0
    for index, elem in enumerate(P8table):
        subKey1 += (128 >> index) * shiftedOnceKey[elem - 1]
        subKey2 += (128 >> index) * shiftedTwiceKey[elem - 1]
    return (subKey1, subKey2)
 
def fk(subKey, inputData):
    """Apply Feistel function on data with given subkey"""
    def F(sKey, rightNibble):
        aux = sKey ^ perm(swapNibbles(rightNibble), EPtable)
        index1 = ((aux & 0x80) >> 4) + ((aux & 0x40) >> 5) + \
                 ((aux & 0x20) >> 5) + ((aux & 0x10) >> 2)
        index2 = ((aux & 0x08) >> 0) + ((aux & 0x04) >> 1) + \
                 ((aux & 0x02) >> 1) + ((aux & 0x01) << 2)
        sboxOutputs = swapNibbles((S0table[index1] << 2) + S1table[index2])
        return perm(sboxOutputs, P4table)
 
    leftNibble, rightNibble = inputData & 0xf0, inputData & 0x0f
    return (leftNibble ^ F(subKey, rightNibble)) | rightNibble
 
def encrypt(key, plaintext):
    """Encrypt plaintext with given key"""
    data = fk(keyGen(key)[0], ip(plaintext))
    return fp(fk(keyGen(key)[1], swapNibbles(data)))
 
def decrypt(key, ciphertext):
    """Decrypt ciphertext with given key"""
    data = fk(keyGen(key)[1], ip(ciphertext))
    return fp(fk(keyGen(key)[0], swapNibbles(data)))  
 """-------end of SDES implementation-------"""

 """Method for double encryption taking key1,key2 and 
 plaintext and returning corresponding ciphertext"""
 
 def double_encrypt(k1,k2,plaintext):
  temp_cipher = encrypt(k1,plaintext)
  ciphertext = encrypt(k2,temp_cipher)
  return ciphertext

"""Method for double decryption taking key1,key2 and 
ciphertext and returning corresponding plaintext"""

def double_decrypt(k1,k2,cipher):
  middle_cipher = decrypt(k2,cipher)
  plain_text = decrypt(k1,middle_cipher)
  return plain_text

  """ asking user to input plaintext in order to get 
  (plaintext,cipherext) pairs to attack"""

plaintext=list()
cipher_text=list()
for i in range(0,5):
  text = int(input("Enter "+ str(i) +" text to encrypt: "))
  plaintext.append(text)

key1 = int(input("Enter key1: "))
key2 = int(input("Enter key2:" ))
for i in range(0,5):
  cipher = double_encrypt(key1,key2,plaintext[i])
  cipher_text.append(cipher)
  print("The cipher for the given input"+ str(i) +" is: ",cipher_text[i])

# MITM

# This table will store middle ciphers that are obtained when ecrypted by 0 to 1024 keys
encrypt_table = dict()

# Here we are generating all middle cipher when we ecnrypt

for i in range(0,1024):
  middle_text = encrypt(i,plaintext[0])

  # Below if condition checks whether the "middle cipher" is present as key in ecrypt_table
  # if the middle cipher exists as a key in this dictionary then we have to append the current ecrypted key into the values
  # Below is the dictionary called ecrypt table

  #    key                value
  # ------------------------------------
  # middle cipher   |  list of keys
  # ------------------------------------
  #      20         |      [1]
  #      125        |      [2,4]
  #      54         |      [3,500,1023]
  # ------------------------------------
  # ecrypt_table = {20 : [1], 125 : [2,4] , 54 : [3,500,1023]}

  if middle_text in encrypt_table:
    encrypt_table[middle_text].append(i)

  # if the middle cipher doesn't exit as a key in the dictionary then it will create this key with a value
  # The value for this would be a list with i appended in it
  # i is the key from 0 to 1023 which resulted in this middle cipher

  else:
    lst = list()
    lst.append(i)
    encrypt_table[middle_text] = lst  # This appends the key i to middle cipher, say x

"""for every possible key(here 1024) we are finding corresponding
middle cipher"""
list3 =  list()

for i in range(1024):
  middle_text = decrypt(i,cipher_text[0])

  if middle_text in encrypt_table:
    for x in encrypt_table[middle_text]: #list of keys in encrypt table
      tup = (i,x)
      list3.append(tup)
    
#printing the length of the list
print("The length of list is: ",len(list3))

""" Method to find the cipher by double encrypting the known plaintext 
and using key2,key1 found above""" 
list4=list()
for i in range(0,len(list3)):
    cipher1 = double_encrypt(list3[i][1],list3[i][0],plaintext[1])
    if cipher1==cipher_text[1]:
        list4.append((list3[i][1],list3[i][0]))
print(list4)            
list5=list()
for i in range(0,len(list4)):
    cipher1 = double_encrypt(list4[i][0],list4[i][1],plaintext[2])
    if cipher1==cipher_text[2]:
        list5.append((list4[i][0],list4[i][1]))
print(list5)
list51=list()
for i in range(0,len(list5)):
    cipher1 = double_encrypt(list5[i][0],list5[i][1],plaintext[3])
    if cipher1==cipher_text[3]:
        list51.append((list5[i][0],list5[i][1]))
print(list51) 
list52=list()
for i in range(0,len(list51)):
    cipher1 = double_encrypt(list51[i][0],list51[i][1],plaintext[4])
    if cipher1==cipher_text[4]:
        list52.append((list51[i][0],list51[i][1]))
print(list52)
list53=list()
for i in range(0,len(list52)):
    cipher1 = double_encrypt(list52[i][0],list52[i][1],plaintext[5])
    if cipher1==cipher_text[5]:
        list53.append((list51[i][0],list51[i][1]))
print("Final pair of the keys(k1,k2) are:",list53)      