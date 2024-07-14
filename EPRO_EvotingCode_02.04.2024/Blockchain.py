
#IMPORTING LIBRARIES
import datetime
import hashlib
import json
from tinyec import registry
from Crypto.Cipher import AES
import secrets
import hashlib, binascii
import pandas as pd
import numpy as np
import os
  
#CREATING BLOCKCHAIN CLASS 
class Blockchain:

    def __init__(self):
        self.chain = []
        self.create_block(proof=1, previous_hash='0')

    def create_block(self, proof, previous_hash):
        block = {'index': len(self.chain) + 1,
                 'timestamp': str(datetime.datetime.now()),
                 'proof': proof,
                 'previous_hash': previous_hash}
        self.chain.append(block)
        return block
        
    def print_previous_block(self):
        return self.chain[-1]
        
    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
          
        while check_proof is False:
            hash_operation = hashlib.sha256(
                str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
                  
        return new_proof
  
    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()
  
    def chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1
          
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
                
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(
                str(proof**2 - previous_proof**2).encode()).hexdigest()
              
            if hash_operation[:4] != '0000':
                return False
            previous_block = block
            block_index += 1
          
        return True

#ECC ENCRYTION AND DECRYPTION WITH AES
def encryption_AES(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def decryption_AES(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ecc_to_256_bitkey(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

curve = registry.get_curve('brainpoolP256r1')


def ECC_Encrytion(msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ecc_to_256_bitkey(sharedECCKey)
    ciphertext, nonce, authTag = encryption_AES(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)

def ECC_Decrytion(storedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = storedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ecc_to_256_bitkey(sharedECCKey)
    plaintext = decryption_AES(ciphertext, nonce, authTag, secretKey)
    return plaintext

#-------------------------------------------------------------------------------------------------
blockchain = Blockchain()
previous_block = blockchain.print_previous_block()
previous_proof = previous_block['proof']
proof = blockchain.proof_of_work(previous_proof)
previous_hash = blockchain.hash(previous_block)
block = blockchain.create_block(proof, previous_hash)

#lOADING DATASET
df=pd.read_csv('database/voterList.csv')


lak = df.to_numpy().flatten()

encrypt = []
decrypt = []
for j in lak:
    j = str(j)
    msg = str.encode(j)    
    privKey = secrets.randbelow(curve.field.n)
    pubKey = privKey * curve.g
    
    encryptedMsg = ECC_Encrytion(msg, pubKey)
    encrypt.append(encryptedMsg)
      
    response = {'message': encryptedMsg,
                'index': block['index'],
                'timestamp': block['timestamp'],
                'proof': block['proof'],
                'previous_hash': block['previous_hash']} 
    response2 = {'chain': blockchain.chain,
                    'length': len(blockchain.chain)} 
    valid = blockchain.chain_valid(blockchain.chain)
          
    if valid:
        print( 'The Blockchain is valid.')
        storedMsg=response["message"]
        #print(storedMsg)
        decryptedMsg = ECC_Decrytion(storedMsg, privKey)
        decryptedMsg = decryptedMsg.decode('utf-8')
        decrypt.append(decryptedMsg)
        
        print("decrypted msg:", decryptedMsg)
    else:
        print( 'The Blockchain is not valid.')
    
"Blockchain Encryption and decryption "

def AES_Encryption(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    return (ciphertext, aesCipher.nonce, authTag)

def AES_Decryption(ciphertext, nonce, authTag, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext

def ECC_bit_key_generation(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

curve = registry.get_curve('brainpoolP256r1')

def ECC_Encryption(msg, pubKey):
    ciphertextPrivKey = secrets.randbelow(curve.field.n)
    sharedECCKey = ciphertextPrivKey * pubKey
    secretKey = ECC_bit_key_generation(sharedECCKey)
    ciphertext, nonce, authTag = AES_Encryption(msg, secretKey)
    ciphertextPubKey = ciphertextPrivKey * curve.g
    return (ciphertext, nonce, authTag, ciphertextPubKey)

def ECC_Decryption(encryptedMsg, privKey):
    (ciphertext, nonce, authTag, ciphertextPubKey) = encryptedMsg
    sharedECCKey = privKey * ciphertextPubKey
    secretKey = ECC_bit_key_generation(sharedECCKey)
    plaintext = AES_Decryption(ciphertext, nonce, authTag, secretKey)
    return plaintext

#----------------------------------------------------------------------------------------


df1 = pd.read_csv("database/voterList.csv") 
df1.shape

column_names = list(df.columns)

result = df.values

print("Encrypting and Decrypting the CSV file...")  
empty = []
empty_decoded = []
for i in result:
    for j in i:
        a = str(j)
        en = a.encode()
        s = ECC_Encrytion(en, pubKey)
        b = binascii.hexlify(s[0])
        encoded_text = b.decode('utf-8')
        empty.append(encoded_text)
        #print(f"Encoded Text : {encoded_text}")
        
        
        de = ECC_Decryption(s, privKey)
        decoded_text = de.decode('utf-8')
        empty_decoded.append(decoded_text)
        #print(f"Decoded Text  : {decoded_text}")
     
encrypted_df = pd.DataFrame(np.array(empty).reshape(df.shape),columns = column_names)
print("Encryption Completed and written as encryption.csv file")
encrypted_df.to_csv(r'voterListencrypted.csv',index = False)
encrypted_df.head()
print("decryption Completed and written as Decryption.csv file")
decrypted_df = pd.DataFrame(np.array(decrypt).reshape(df.shape),columns =df.columns)
decrypted_df.to_csv(r'voterListdecryption.csv',index = False)
decrypted_df.head()  

