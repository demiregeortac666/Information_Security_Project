import hashlib 
import os
import json 
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


#Absolute path to the file to be hashed. 
FILES_PATH = "/Users/demiregeortac/Desktop/trustverify_project/files/"
BASE_PATH = "/Users/demiregeortac/Desktop/trustverify_project/"

def file_hash(file_path):
    with open(file_path, "rb") as f:
        content = f.read()
    hash = hashlib.sha256(content)
    return hash.hexdigest()


def generate_manifest(FILES_PATH):
    manifest = {}
    files = os.listdir(FILES_PATH)
    for file in files:
        file_path = os.path.join(FILES_PATH, file)
        if not os.path.isfile(file_path) or file == "manifest.json":
            continue
        hash_of_file = file_hash(file_path)
        manifest[file] = hash_of_file
    
    with open(os.path.join(FILES_PATH, "manifest.json"),"w") as manifest_file:
        json.dump(obj= manifest, fp= manifest_file, indent = 4)
        print("The manifest of the directory was created successfully!")


def check_integrity(dir_path):
    new_manifest = {}
    with open(os.path.join(dir_path, "manifest.json"), "r") as old_manifest_file:
        old_manifest = json.load(old_manifest_file)
    files = os.listdir(dir_path)
    for file in files: 
        file_path = os.path.join(dir_path, file)
        if not os.path.isfile(file_path) or file == "manifest.json":
            continue
        hash_of_file = file_hash(file_path)
        new_manifest[file] = hash_of_file
    
    for file_name in old_manifest:
        if file_name in new_manifest:
            if old_manifest[file_name] != new_manifest[file_name]:
                print(f"Tampered:{file_name}")
            else:
                print(f"OK:{file_name}")
        else:
            print(f"Missing:{file_name}")

        


def generate_keys():
    private_key = rsa.generate_private_key(key_size = 2048, public_exponent=65537)
    public_key = private_key.public_key()
    os.makedirs(os.path.join(BASE_PATH, "keys"), exist_ok=True)
    with open(os.path.join(BASE_PATH,"keys", "private_key.pem"), "wb") as private_key_file:
            private_key_file.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                             format=serialization.PrivateFormat.PKCS8,
                                                             encryption_algorithm=serialization.NoEncryption()))
            
    with open(os.path.join(BASE_PATH,"keys","public_key.pem"), "wb") as public_key_file:
        public_key_file.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                                      format = serialization.PublicFormat.SubjectPublicKeyInfo))
    print("Public and private key were generated successfully.")   

def sign():
    
    
    with open(os.path.join(BASE_PATH,"keys","private_key.pem"),"rb") as private_key_pem:
        private_key_data = private_key_pem.read()
    private_key = serialization.load_pem_private_key(data= private_key_data, password=None)
    manifest_hash_string = file_hash(os.path.join(FILES_PATH,"manifest.json"))
    manifest_hash_bytes = manifest_hash_string.encode()
    signature = private_key.sign(
        data = manifest_hash_bytes,
        padding=padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        algorithm=hashes.SHA256()
    )

    os.makedirs(os.path.join(BASE_PATH,"signiture_bins"), exist_ok = True)
    with open(os.path.join(BASE_PATH,"signiture_bins", "signature.bin"), "wb") as signature_bin:
        signature_bin.write(signature)

        


def verify():
    with open(os.path.join(BASE_PATH,"keys", "public_key.pem"), "rb") as public_key:
        public_key_data = public_key.read()
    public_key = serialization.load_pem_public_key(public_key_data)

    manifest_hash_string = file_hash(os.path.join(FILES_PATH,"manifest.json"))
    manifest_hash = manifest_hash_string.encode()

    with open(os.path.join(BASE_PATH,"signiture_bins","signature.bin"), "rb") as signature_file:
        signature_data = signature_file.read()
    
    
    try:
        public_key.verify(
            signature_data,
            manifest_hash,
            padding.PSS(
            mgf = padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256())
        print("Signature is Valid!")

    except:
        print("Signature is invalid")
    




                                  
                                  



        









#generate_manifest(FILES_PATH)
#sign()
#change test.txt


check_integrity(FILES_PATH)
verify()



