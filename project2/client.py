"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

from base_client import BaseClient, IntegrityError
from crypto import CryptoError
from util import *


def path_join(*strings):
    """Joins a list of strings putting a "/" between each.

    :param strings: a list of strings to join
    :returns: a string
    """
    return '/'.join(strings)

def mult_8(message):
    return ((len(message)//8) + 1) * 8

class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)

        #encrypt the symmetric key using asymm encrypt
        n = 16
        key1 = self.crypto.get_random_bytes(n)
        key2 = self.crypto.get_random_bytes(n)
        public_key = self.pks.get_public_key(self.username)
        enc_symmkey1 = self.crypto.asymmetric_encrypt(key1, public_key)
        enc_symmkey2 = self.crypto.asymmetric_encrypt(key2, public_key)

        #Asymmetrically sign the encrypted symmetric key
        asymm_sign1 = self.crypto.asymmetric_sign(enc_symmkey1, self.private_key)
        asymm_sign2 = self.crypto.asymmetric_sign(enc_symmkey2, self.private_key)
        #first 64 bytes signature, rest is the messsage
        dict_keys = {
                        "ENC": {
                            "SIG": asymm_sign1, 
                            "KEY": enc_symmkey1
                            },

                        "MAC": {
                            "SIG": asymm_sign2, 
                            "KEY": enc_symmkey2
                            }
                    }

        self.storage_server.put(path_join(self.username, "dir_keys"), to_json_string(dict_keys))

    """ *********************************** HELPER METHODS ************************************* """

    """ ---------------------------INTEGRITY HELPERS --------------------------"""
    #Helper function used to check integrity of symmetric keys
    def check_integrity_keys(self, pub_key, key_dict):
        for key, value in key_dict.items():
            curr_sig = value["SIG"]
            curr_symm = value["KEY"]
            asymm_verify = self.crypto.asymmetric_verify(message = curr_symm, signature=curr_sig, public_key=pub_key)
            if not asymm_verify:
                return False
        return True

    #Helper function to check integrity of RSA only
    def check_integrity_RSA(self, key, key_dict):
        signature = key_dict["SIG"]
        symm = key_dict["KEY"]
        asymm_verify = self.crypto.asymmetric_verify(message = symm, signature=signature, public_key=key)

    #Helper function to check integrity of MAC //TODO why is there a keyerror here?
    def check_integrity_MAC(self, key, key_dict):
        curr_MAC = key_dict["MAC"]
        curr_msg = key_dict["MSG"]
        MAC = self.crypto.message_authentication_code(message=curr_msg, key=key, hash_name="MD5")
        return MAC == curr_MAC

    """ ---------------------------ENCRYPTION HELPERS -------------------------"""
    #encrypts message and generates a mac for it
    def symmetric_encrypt_and_mac(self, message, enc_key, mac_key, IV):
        #encrypt message with symm_key_enc
            enc_message = self.crypto.symmetric_encrypt(message=message, key=enc_key, cipher_name="AES", mode_name='CBC', IV=IV)
            enc_message_IV = IV + enc_message

            #generate MAC and add MAC in front of enc_message
            MAC = self.crypto.message_authentication_code(message=enc_message_IV, key=mac_key, hash_name="MD5")
            enc_data = to_json_string({"MAC": MAC, "MSG": enc_message_IV})
            return enc_data

    """ ---------------------------DECRYPTION HELPERS -------------------------"""
    #Separates msg into IV and message and returns them in a list
    def IV_separation(self, msg):
        IV = msg[:32]
        rest = msg[32:]
        return [IV, rest]

    """ ---------------------------RETRIEVAL HELPERS --------------------------"""
    #assumes symmetric keys exist and returns key_dict object
    def retrieve_symmetric_keys(self):
        try:
            return from_json_string(self.storage_server.get(path_join(self.username, "dir_keys")))
        except:
            raise IntegrityError()

    #retrieves mac/enc msg and returns dictionary 
    def retrieve_mac_enc_msg(self, path):
        try:
            return from_json_string(self.storage_server.get(path))
        except:
            return IntegrityError()

    #assumes that integrity has already been checked
    def decrypt_symmetric_keys(self, private_key, key_dict):
        lst = []
        for key, value in key_dict.items():
            dec_symmkey = self.crypto.asymmetric_decrypt(value["KEY"], self.private_key)
            lst.append(dec_symmkey)
        return lst

    #Resolves the file and checks if it is None 
    def resolve(self, uid):
        while True:
            res = self.storage_server.get(uid)
            if res is None:
                return None
            elif res:
                return res
            else:
                raise IntegrityError()

    """ *********************************** END HELPERS ************************************* """

    def upload(self, name, value):
        #upload with a binary tree to store the data

        #hash_name
        hash_name = self.crypto.cryptographic_hash(name, hash_name="MD5")

        #encrypt the message
        IV = self.crypto.get_random_bytes(16)
        #check and decrypt symmetric key
        try:
            keys = from_json_string(self.storage_server.get(path_join(self.username, "dir_keys")))
        except:
            raise IntegrityError()

        public_key = self.pks.get_public_key(self.username)
        #if integrity intact, decrypt
        if self.check_integrity_keys(public_key, keys):
            #decrypt symm_key
            dec_key_enc, dec_key_mac = self.decrypt_symmetric_keys(self.private_key, keys)

            enc_data = self.symmetric_encrypt_and_mac(value, dec_key_enc, dec_key_mac, IV)

            #hash name and place it at path/hashname
            path = path_join(self.username, hash_name)

            #combine MAC and message
            self.storage_server.put(path, enc_data)

            #upload succeeded
            return True

        else:
            #if integrity fails
            return False

    def download(self, name):
        #save public key for later use
        public_key = self.pks.get_public_key(self.username)

        #hash_name for file
        hash_name = self.crypto.cryptographic_hash(name, hash_name="MD5")

        #path with hash_name
        path = path_join(self.username, hash_name)

        #check if enc_message
        mac_enc_msg = self.resolve(path)

        #verify it exists
        if mac_enc_msg is None:
            return None
        else:
            try:
                mac_enc_msg = from_json_string(mac_enc_msg)
            except:
                raise IntegrityError()

        #get the symmetric key
        keys = self.retrieve_symmetric_keys()
        dec_symmkey = None

        #check integrity of symmetric_key
        if self.check_integrity_keys(public_key, keys):
            dec_key_enc, dec_key_mac = self.decrypt_symmetric_keys(self.private_key, keys)
        else:
            raise IntegrityError()

        #check integrity encrypted message and then proceed
        if self.check_integrity_MAC(dec_key_mac, mac_enc_msg):
            IV, enc_msg = self.IV_separation(mac_enc_msg["MSG"])
            try: 
                #try decrypting
                dec_message = self.crypto.symmetric_decrypt(ciphertext=enc_msg, key=dec_key_enc, cipher_name="AES", mode_name="CBC", IV=IV)
                return dec_message
            except: 
                raise IntegrityError()
        else:
            raise IntegrityError()
    
    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        #use json to string, string to json 
        #alice needs to send message saying "alice/sharewith/bob/file.txt"
        #alice puts json object on server
        #json contains symm key for MAC
        #   symm key ENC for data 
        # type?
        # and then the encrypted message "alice...file.txt" that is encrypted with symm key ENC which is asymmetrically encrypt
        #the json obj is asymmetrically encrypted with bobs public key

        #GET THE JSON OBJ OF SIG AND KEY FROM THE SERVER AND CHECK IF ITS COMPROMISED
        try:
            keys = from_json_string(self.storage_server.get(path_join(self.username, "dir_keys")))
        except:
            raise IntegrityError()
        #get alice's public key to check integrity
        public_key = self.pks.get_public_key(self.username)
        bobs_public_key = self.pks.get_public_key(user)
        #IF SIG AND KEY FROM SERVER NOT COMPROMISED DECRYPT THEM AND THEN REPACKAGE THEM W ASYMM ENC W BOB
        if self.check_integrity_keys(public_key, keys):
            #decrypt symm_key
            dec_key_enc, dec_key_mac = self.decrypt_symmetric_keys(self.private_key, keys)

            #ASYMM ENCRYPT W BOBS PUBLIC KEY
            enc_symmkey1 = self.crypto.asymmetric_encrypt(dec_key_enc, bobs_public_key)
            enc_symmkey2 = self.crypto.asymmetric_encrypt(dec_key_mac, bobs_public_key)

            #Asymmetrically sign the encrypted symmetric key (RSA) 
            #what is the point of authenticating this? want to make sure alice sent this to bob
            #so bob needs to pull alice's public key in order to verify within receive_share()

            asymm_sign1 = self.crypto.asymmetric_sign(enc_symmkey1, self.private_key)
            asymm_sign2 = self.crypto.asymmetric_sign(enc_symmkey2, self.private_key)

            #message = "alice/sharewith/bob/name.txt"
            message = path_join(self.username, "sharewith", user, name)
            #***I didnt hash the filename? not sure what we have to do with that
            self.storage_server.put(message,
                                "[POINTER] " + path_join(self.username, name))

            IV = self.crypto.get_random_bytes(16)
            
            #symm encrypt this message = "alice/sharewith...etc." with decrypted symm key. 
            #we send this symm key encrypted with bob's pub key in the package
            message_to_bob = IV + self.crypto.symmetric_encrypt(message=message, key=dec_key_enc, cipher_name="AES", mode_name='CBC', IV=IV)
            #generate MAC and add MAC in front of the encrypted message (USED SHA256)
            #want to keep integrity of this message
            #for Bob to check integrity, he needs to check if given MAC == MAC(MSG["MSGMAC"])
            #is it fine to use same key for mac? for both integrity of keys and integrity of message?

            MAC = self.crypto.message_authentication_code(message=message_to_bob, key=dec_key_mac, hash_name="SHA256")
            #mac_message_to_bob = to_json_string({"MAC": MAC, "MSG": message_to_bob})

            package_to_send = {
                            "ENC": {
                                "SIG": asymm_sign1, 
                                "KEY": enc_symmkey1
                                },

                            "MAC": {
                                "SIG": asymm_sign2, 
                                "KEY": enc_symmkey2
                                },
                            "MSG": {
                                "CONTENT": message_to_bob,
                                "MSGMAC": MAC
                                }
                            }

            send_this = to_json_string(package_to_send)

            #do we know that the json obj can be passed to bob safely? 
            #we need to send to bob the json object containing: enc, mac, msg, msg mac
            return send_this
        else:
            raise IntegrityError()
        

        #raise NotImplementedError

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        #FIRST UNPACK MESSAGE 
        msg = from_json_string(message)
        bobs_public_key = self.pks.get_public_key(self.username)
        alices_public_key = self.pks.get_public_key(from_username)

        msg_enc = msg["ENC"]
        msg_mac = msg["MAC"]
        msg_enc_sig = msg_enc["SIG"]
        msg_mac_sig = msg_mac["SIG"]
        msg_enc_key = msg_enc["KEY"]
        msg_mac_key = msg_mac["KEY"]

        asymm_verify1 = self.crypto.asymmetric_verify(message=msg_enc_key, signature=msg_enc_sig, public_key=alices_public_key)
        asymm_verify2 = self.crypto.asymmetric_verify(message=msg_mac_key, signature=msg_mac_sig, public_key=alices_public_key)

        if asymm_verify1 and asymm_verify2:
            # lst = []
            # for key, value in msg.items():
            #     if value["KEY"]:    
            #         dec_symmkey = self.crypto.asymmetric_decrypt(value["KEY"], self.private_key)
            #         lst.append(dec_symmkey)
            # symmkey1 = lst[0]
            # symmkey2 = lst[1]
            symmkey1 = self.crypto.asymmetric_decrypt(msg_enc_key, self.private_key)
            symmkey2 = self.crypto.asymmetric_decrypt(msg_mac_key, self.private_key)

            #decrypt message
            enc_message_section = msg["MSG"]
            enc_content = enc_message_section["CONTENT"]
            givenmac = enc_message_section["MSGMAC"]

            if (self.crypto.message_authentication_code(message=enc_content, key=symmkey2, hash_name="SHA256") == givenmac):
                #decrypt message after auth
                IV, enc_content_minusIV = self.IV_separation(enc_content)
                #dec_content = self.crypto.symmetric_decrypt()
                try: 
                    #try decrypting
                    dec_message = self.crypto.symmetric_decrypt(ciphertext=enc_content_minusIV, key=symmkey1, cipher_name="AES", mode_name="CBC", IV=IV)
                    #now bob has "alice/.../filename.txt so we can create a symlink"
                    self.storage_server.put(path_join(self.username, newname), "[POINTER] " + dec_message)

                except: 
                    raise IntegrityError()

        else:
            raise IntegrityError()

                    


                        




        #raise NotImplementedError

    def revoke(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        raise NotImplementedError
