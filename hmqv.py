from binascii import hexlify
from hashlib import sha256
from os import urandom
from gmssl import sm3

primes = {
            
    # 1536-bit
    5: {
            
        "prime": int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            + "670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF",
            base=16,
        ),
        "generator": 2,
    },
    # 2048-bit
    14: {
            
        "prime": int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            + "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
            base=16,
        ),
        "generator": 2,
    },
    # 3072-bit
    15: {
            
        "prime": int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            + "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
            + "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
            + "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
            + "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
            + "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
            + "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
            base=16,
        ),
        "generator": 2,
    },
    # 4096-bit
    16: {
            
        "prime": int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            + "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
            + "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
            + "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
            + "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
            + "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
            + "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
            + "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
            + "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
            + "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
            + "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
            + "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199"
            + "FFFFFFFFFFFFFFFF",
            base=16,
        ),
        "generator": 2,
    },
    # 6144-bit
    17: {
            
        "prime": int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
            + "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B"
            + "302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9"
            + "A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE6"
            + "49286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8"
            + "FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C"
            + "180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718"
            + "3995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D"
            + "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7D"
            + "B3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D226"
            + "1AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
            + "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFC"
            + "E0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B26"
            + "99C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB"
            + "04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2"
            + "233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127"
            + "D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
            + "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BDF8FF9406"
            + "AD9E530EE5DB382F413001AEB06A53ED9027D831179727B0865A8918"
            + "DA3EDBEBCF9B14ED44CE6CBACED4BB1BDB7F1447E6CC254B33205151"
            + "2BD7AF426FB8F401378CD2BF5983CA01C64B92ECF032EA15D1721D03"
            + "F482D7CE6E74FEF6D55E702F46980C82B5A84031900B1C9E59E7C97F"
            + "BEC7E8F323A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
            + "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE32806A1D58B"
            + "B7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55CDA56C9EC2EF29632"
            + "387FE8D76E3C0468043E8F663F4860EE12BF2D5B0B7474D6E694F91E"
            + "6DCC4024FFFFFFFFFFFFFFFF",
            base=16,
        ),
        "generator": 2,
    },
    # 8192-bit
    18: {
            
        "prime": int(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
            + "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
            + "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
            + "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            + "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
            + "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
            + "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            + "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
            + "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
            + "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
            + "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
            + "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
            + "43DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D7"
            + "88719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA"
            + "2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6"
            + "287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED"
            + "1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA9"
            + "93B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934028492"
            + "36C3FAB4D27C7026C1D4DCB2602646DEC9751E763DBA37BD"
            + "F8FF9406AD9E530EE5DB382F413001AEB06A53ED9027D831"
            + "179727B0865A8918DA3EDBEBCF9B14ED44CE6CBACED4BB1B"
            + "DB7F1447E6CC254B332051512BD7AF426FB8F401378CD2BF"
            + "5983CA01C64B92ECF032EA15D1721D03F482D7CE6E74FEF6"
            + "D55E702F46980C82B5A84031900B1C9E59E7C97FBEC7E8F3"
            + "23A97A7E36CC88BE0F1D45B7FF585AC54BD407B22B4154AA"
            + "CC8F6D7EBF48E1D814CC5ED20F8037E0A79715EEF29BE328"
            + "06A1D58BB7C5DA76F550AA3D8A1FBFF0EB19CCB1A313D55C"
            + "DA56C9EC2EF29632387FE8D76E3C0468043E8F663F4860EE"
            + "12BF2D5B0B7474D6E694F91E6DBE115974A3926F12FEE5E4"
            + "38777CB6A932DF8CD8BEC4D073B931BA3BC832B68D9DD300"
            + "741FA7BF8AFC47ED2576F6936BA424663AAB639C5AE4F568"
            + "3423B4742BF1C978238F16CBE39D652DE3FDB8BEFC848AD9"
            + "22222E04A4037C0713EB57A81A23F0C73473FC646CEA306B"
            + "4BCBC8862F8385DDFA9D4B7FA2C087E879683303ED5BDD3A"
            + "062B3CF5B3A278A66D2A13F83F44F82DDF310EE074AB6A36"
            + "4597E899A0255DC164F31CC50846851DF9AB48195DED7EA1"
            + "B1D510BD7EE74D73FAF36BC31ECFA268359046F4EB879F92"
            + "4009438B481C6CD7889A002ED5EE382BC9190DA6FC026E47"
            + "9558E4475677E9AA9E3050E2765694DFC81F56E880B96E71"
            + "60C980DD98EDD3DFFFFFFFFFFFFFFFFF",
            base=16,
        ),
        "generator": 2,
    },
}


class HMQV:
    """
    Class to represent the Diffie-Hellman key exchange protocol


    >>> client = HMQV(True)
    >>> server = HMQV(False)

    >>> client_static_private = client.get_static_private_key()
    >>> client_static_public = client.generate_static_public_key()

    >>> client_ephemeral_private = client.get_ephemeral_private_key()
    >>> client_ephemeral_public = client.generate_ephemeral_public_key()

    >>> server_static_private = server.get_static_private_key()
    >>> server_static_public = server.generate_static_public_key()

    >>> server_ephemeral_private = server.get_ephemeral_private_key()
    >>> server_ephemeral_public = server.generate_ephemeral_public_key()

    >>> # generating shared key using the DH object
    >>> client_shared = client.generate_shared_key(client_ephemeral_public,server_static_public,server_ephemeral_public)
    >>> server_shared = server.generate_shared_key(server_ephemeral_public,client_static_public,client_ephemeral_public)

    >>> assert client_shared == server_shared

    """

    # Current minimum recommendation is 2048 bit (group 14)
    def __init__(self, isClient, static_private_key, group: int = 14) -> None:
        if group not in primes:
            raise ValueError("Unsupported Group")
        self.prime = primes[group]["prime"]
        self.generator = primes[group]["generator"]
        self.isClient = isClient

        self.__static_private_key = static_private_key  #int(hexlify(urandom(32)), base=16)
        self.__ephemeral_private_key = int(hexlify(urandom(32)), base=16)


    def get_ephemeral_private_key(self) -> str:
        return hex(self.__ephemeral_private_key)[2:]

    def generate_ephemeral_public_key(self) -> str:
        public_key = pow(self.generator, self.__ephemeral_private_key, self.prime)
        return hex(public_key)[2:]

    def get_static_private_key(self) -> str:
        return hex(self.__static_private_key)[2:]

    def generate_static_public_key(self) -> str:
        public_key = pow(self.generator, self.__static_private_key, self.prime)
        return hex(public_key)[2:]

    def is_valid_public_key(self, key: int) -> bool:
        # check if the other public key is valid based on NIST SP800-56
        if 2 <= key and key <= self.prime - 2:
            if pow(key, (self.prime - 1) // 2, self.prime) == 1:
                return True
        return False

    def generate_shared_key(self, self_ephemeral_key_str: str,other_static_key_str: str, other_ephemeral_key_str: str,cIP) -> str:
        

        
        other_static_key = int(other_static_key_str, base=16)
        other_ephemeral_key = int(other_ephemeral_key_str, base=16)
        if not self.is_valid_public_key(other_static_key):
            raise ValueError("Invalid static public key")
        if not self.is_valid_public_key(other_ephemeral_key):
            raise ValueError("Invalid ephemeral public key")
        if self.isClient:
            data1 = self_ephemeral_key_str+"honeychecker"
            data2 = other_ephemeral_key_str+cIP
            #print("这是客户端"+cIP)

            d = int(sm3.sm3_hash(list(str(data1).encode())),base=16)
            e = int(sm3.sm3_hash(list(str(data2).encode())),base=16)
            #f = int(sm3.sm3_hash(list(str(data3).encode())),base=16)
            #d = int(sha256(str(data1).encode()).hexdigest(),base=16)
            #e = int(sha256(str(data2).encode()).hexdigest(),base=16)
            exp = (self.__ephemeral_private_key + d * self.__static_private_key) % self.prime
            base = (other_ephemeral_key * pow(other_static_key,e,self.prime)) % self.prime
            shared_key = pow(base, exp, self.prime)
        else:
            data1 = other_ephemeral_key_str+"honeychecker"
            data2 = self_ephemeral_key_str+cIP
            #print("这是服务器"+cIP)
            d = int(sm3.sm3_hash(list(str(data1).encode())),base=16)
            e = int(sm3.sm3_hash(list(str(data2).encode())),base=16)
            #f = int(sm3.sm3_hash(list(str(data3).encode())),base=16)
            #d = int(sha256(str(data1).encode()).hexdigest(),base=16)
            #e = int(sha256(str(data2).encode()).hexdigest(),base=16)
            exp = (self.__ephemeral_private_key + e * self.__static_private_key) % self.prime
            base = (other_ephemeral_key * pow(other_static_key,d,self.prime)) % self.prime
            shared_key = pow(base, exp, self.prime)
        return sm3.sm3_hash(list( str(shared_key).encode() ) )
        #return sha256(str(shared_key).encode()).hexdigest()


if __name__ == "__main__":
    import doctest

    doctest.testmod(verbose=True)

