import binascii
import RSA_TAPI_YANG_GACOR

class RSA:

    @staticmethod
    def load_pub(key_path: str):
        key_file = open(key_path)
        (pub, n) = [int(line) for line in key_file.readlines()]
        key_file.close()
        return (pub, n)
    
    @staticmethod
    def load_priv(key_path: str):
        file = open(key_path)
        priv = int(file.readline())
        file.close()
        return priv
    
    @staticmethod
    def save_pub(key_name: str, pub_key: int, modulus: int):
        file = open(key_name + ".pub", 'w+')
        file.write(str(pub_key) + '\n')
        file.write(str(modulus))
        file.close()

    @staticmethod
    def save_priv(key_name: str, priv_key: int):
        file = open(key_name, 'w+')
        file.write(str(priv_key))
        file.close()

    def __init__(self, priv_key = 0, n = 0) -> None:
        self.priv = priv_key
        self.n = n
        pass
    
    # priv_key = -1
    # pub_key = -1
    # def load_priv(self, file_path: str):
    #     file = open(file_path)
    #     self.priv_key = int(file.readline())


    # def load_pub(self, file_path: str):
    #     file = open(file_path)
    #     self.pub_key = file.readline()

    @staticmethod
    def eea(a, b, x, y):
        if(b == 0):
            x = 1
            y = 0
            return (a, x, y)
        
        (d,x1,y1) = RSA.eea(b, a % b, 1, 0)
        c = y1
        e = x1 - y1 * (a // b)

        return (d, c, e)

    @staticmethod
    def mod_inv(a, m):
        (gcd, x, _) = RSA.eea(a, m, 1, 0)
        if(gcd != 1):
            raise ValueError("ga bener jir")
        else:
            x = (x % m + m) % m
            return x
    
    @staticmethod
    def generate_key() -> tuple[int, int, int]:
        p = RSA_TAPI_YANG_GACOR.random_prime(1024)
        q = RSA_TAPI_YANG_GACOR.random_prime(1024)

        # p = 11
        # q = 13
        while p == q:
            q = RSA_TAPI_YANG_GACOR.random_prime(1024)
            

        n = p * q
        phi_n = (p - 1) * (q - 1)

        pub_key = 65537
        # while math.gcd(pub_key, phi_n) != 1:
        #     pub_key = random.randint(3, phi_n-1)

        priv_key = RSA.mod_inv(pub_key, phi_n)

        return (priv_key, pub_key, n)

    def str_to_int(self, message):
        message_hex = binascii.hexlify(message.encode())
        message_int = int(message_hex, 16)
        return message_int
    
    def int_to_str(self, num):
        decipher_hex = hex(num).removeprefix('0x')
        try:
            return binascii.unhexlify(decipher_hex).decode('utf-8')
        except UnicodeDecodeError:
        # Jika terjadi error decoding, abaikan karakter yang tidak dapat didekode
            return binascii.unhexlify(decipher_hex).decode('utf-8', errors='ignore')

    def encrypt(self, message, pub_key: tuple[int, int]):
        message_int = self.str_to_int(message)
        return pow(message_int, pub_key[0], pub_key[1])
    
    def sign(self, message, priv_key: tuple[int, int] = (0, 0)):
        message_int = self.str_to_int(message)
        return pow(message_int, priv_key[0], priv_key[1])
    
    def decrypt(self, ciphertext, priv_key: tuple[int, int] = (0, 0)):
        if(priv_key == (0, 0)):
            priv_key = (self.priv, self.n)
        decipher_int = pow(int(ciphertext), priv_key[0], priv_key[1])
        message = self.int_to_str(decipher_int)
        return message
        
    def validate(self, sign, pub_key: tuple[int, int]): #signature, pub_key):
        designatured = pow(sign, pub_key[0], pub_key[1])
        return self.int_to_str(designatured)



if __name__ == '__main__':
    RSA(1,1).print_data()

    # (ali_priv, ali_pub, ali_n) = rsa.generate_key()
    # print(ali_priv)
    # print()
    # print(ali_pub)
    # print()
    # print(ali_n)
    # (wawa_priv, wawa_pub, wawa_n) = rsa.generate_key()
    # # SCENARIO: wawa sends message to ali

    # # =============== WAWA's SIDE ===================
    # # 1. Encrypt message to ALI with ALI's PUBLIC key
    # message = "gua sangat unmotivated hari ini"
    # print("Message:", message)
    # cipher = rsa.encrypt(message, (ali_pub, ali_n))
    # print()
    # print("Encrypted message:", cipher)
    # # 2. Give something that can be used as a sign for ali to prove that "ini rill gw njir", encrypt that with WAWA's PRIVATE key
    # # For the sake of demonstration, here u uses first 10 characters of the message (or the message itself if it's smaller than 10 characters)
    # print()
    # if len(message) >= 10:
    #     frac = message[:10]
    # else:
    #     frac = message
    # print("Sign:", frac)
    # print()

    # sign = rsa.sign(frac, (wawa_priv, wawa_n))
    # print("Encrypted sign:",sign)
    # print()

    # # sends the cipher and the sign to ali

    # # ============== ALI's SIDE ====================
    # # 3. Decrypt MESSAGE that ALI RECEIVED with ALI's PRIVATE key
    # decipher = rsa.decrypt(cipher, (ali_priv, ali_n))
    # print("Decrypted Message:", decipher)
    # print()
    # # 4. Decipher the SIGN with WAWA's PUBLIC key and compare it if it's equal with the object that u marked previously as a sign (that 10 characters)

    # deciphered_sign = rsa.validate(sign, (wawa_pub, wawa_n))
    # print("Decrypted sign:", deciphered_sign)
    # print()
    # # if it's equal, then it's really u who sent it, if it's not than it's not u (maybe someone pretends to be u or sumn)

