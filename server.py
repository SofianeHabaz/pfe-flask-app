from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
import base64
#from services import *
import random
from Crypto.Hash import SHA256

app = Flask(__name__)


prime = int('2519590847565789349402718324004839857142928212620403202777713783604366202070759555626401852588078440319989000889524345065854122758866688128587994947295862217267141979470472965420143143795456620222894513280219498070259966552162299342219321326844827929251973103819829821622445966589517287470093510435292976797507737790503236678909283015000734176730575835889059968026457832840035684297260429891061074821074388469629237581865175912064925096551495638841291927263901336308286602687269310282869331393304719337733344535422019926721680085385725646120332007023784237275458593770238788380303516666348330953849225241878667384160471232398798549252973532603871132889585584845987538896458580147290431254862178712094379024038050216422992278778861674962467606049291502693741747220284895508152116175869202624981225204862749658373128982055872146607625594321939210117046603778962636623940811418265860012799274421139910737649870489438719907779821118960331465310620710137480106982340634643619033723152504672548729892523722184419268358439923702724601654766828771153178402560248163882946092156369877902399642605223943262896569260602112916760348399219909796026186831302675752064202048659254011660969414138496445873332821688424743753514572540936618272375309662270870267494380651029694295')
generator = 2
# Constants for AES encryption
KEY_LENGTH = 16  # AES key length in bytes (16 bytes = 128 bits)
IV = b'df1e180949793972'  # Fixed IV for AES

#declaring cipher variable that holds the aes key generated after the key exchange
aesEncrypter = None
bob_private_key = random.getrandbits(256)
bob_public_key = pow(generator, bob_private_key, prime)
aesKey = None
salt = bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
def derive_aes_key(shared_secret):
    #print("shared secret" + str(shared_secret))
    # Use PBKDF2 to derive AES key from shared secret
    global salt
    print("shared -----> "+str(hex(shared_secret)))
    aes_key = PBKDF2(password=str(hex(shared_secret)), salt=salt,hmac_hash_module=SHA256)
    return aes_key

@app.route('/key-exchange', methods=['POST'])
def key_exchange():
    global aesEncrypter
    global IV
    global aesKey
    
    data = request.get_json()
    alice_public_key = int(data['alicePublicKey'])
    shared_secret = pow(alice_public_key, bob_private_key, prime)
    print("shared secret: "+str(shared_secret))
    # Derive AES key from the shared secret
    aesKey = derive_aes_key(shared_secret)
    print("aes key: "+str(aesKey))
    #print(bytes(aes_key))
    #print(aes_key)
    # Decrypt using AES with the derived key and fixed IV
    aesEncrypter = AES.new(aesKey, AES.MODE_CBC, IV)
    return jsonify({'bobPublicKey': str(bob_public_key)})

def decrypt(data):
    global aesEncrypter
    global aesKey
    global IV
    print("hadi data: ",data)
    # Decode the base64-encoded data
    #print("9bel ",aesEncrypter)
    encrypted_bytes = base64.b64decode(data)
    decrypted_bytes = aesEncrypter.decrypt(encrypted_bytes)
    #print("dec bytes : " , decrypted_bytes)
    decrypted_data = unpad(decrypted_bytes, 16)
    print("this is the data: " + str(decrypted_data))
    print("mor ",aesEncrypter)
    aesEncrypter = AES.new(aesKey, AES.MODE_CBC, IV)
    return decrypted_data

@app.route('/data', methods=['POST'])
def handle_post():
    data = request.get_json()['image']
    decrypted_data = decrypt(data)
    print("decrypted data: ",decrypted_data)
    image_data = base64.b64decode(decrypted_data)
    with open("image.jpg", "wb") as binary_file:
        binary_file.write(image_data)
    data = request.get_json()['location']
    location_data = base64.b64decode(decrypt(data))
    with open("location.txt", "wb") as binary_file:
        binary_file.write(location_data)
    return "Received", 200


@app.route('/', methods=['GET'])
def getreq():
    return "Received", 200

if __name__ == '__main__':
    app.run(debug=True, port=8000, host="172.25.10.111")
