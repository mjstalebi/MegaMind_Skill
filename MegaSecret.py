from flask import Flask, request, jsonify
import json

from ask_sdk_core.skill_builder import SkillBuilder
from ask_sdk_core.dispatch_components import AbstractRequestHandler
from ask_sdk_core.utils import is_request_type, is_intent_name
from ask_sdk_core.handler_input import HandlerInput
from ask_sdk_model.ui import SimpleCard
from ask_sdk_model import Response, RequestEnvelope

#for Asymetric public/private key encryption
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import base64
#for symetric AES
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CBC,OFB,CFB
from hashlib import sha3_256
from os import urandom
from cryptography.hazmat.backends import default_backend

backend = default_backend()
class AES_Cipher:
  def __init__(self,key):
    self.key = key

  def encrypt(self,plain_text):
    initialization_vector = urandom(16)
    cipher = Cipher(AES(self.key),OFB(initialization_vector),backend)
    encryption_engine = cipher.encryptor()
    return initialization_vector + encryption_engine.update(plain_text.encode("utf-8")) + encryption_engine.finalize()

  def decrypt(self,cipher_text):
    initialization_vector = cipher_text[:16]
    cipher = Cipher(AES(self.key),OFB(initialization_vector),backend)
    decryption_engine = cipher.decryptor()
    return (decryption_engine.update(cipher_text[16:]) + decryption_engine.finalize()).decode("utf-8")

AES_engine = AES_Cipher("")

app = Flask(__name__)
sb = SkillBuilder()

user_name = "Bob"
friend_name = "Alice"
count = 0
rsa_key = b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,F039845938688FA23061D24753A3DBF4\n\nfDtwuM+3UjTbrCZaLuS0UqTGGRF5xIvuOqTXHnOA3IZxIChEjxvIU0y8IuaIcqHJ\nHHlQ+siKmqZoBUgFiw0Hm+lnYg7O2zkii7ULGx9VR2gbKkNqMWsDYJkFqFLFzUa0\ne2LhyJ8/JXpuAyGwUM/AXWKsshd2t2u8uoYmvEOEwCn0XERLFHkPuUIaxuiQCWxt\nRzKlSopwQUGxVJ/OcBMvn2ZTR63+2dvonk1zbOK7Vc6S/JKr0ic+Xhtlxv8Ka3Lk\ntHf8NMwu0pRi+EnFQ8nWw8u8jb7BwKT46FoqZlGFAvNGElmpua4a5551vXvihwJd\nCKW2I7VXxgR2B0N7ZjT6XHIkFs4yvvdYLvKByyWmfV+rHJl/0KQqr0CQ+EKjBX35\nDHJRBdm3Fyh5fhut55yyY+IuEwhhMgOW7dlxxujsL403KEyCwDq3dsizSfOMnwta\nI4BF3H7E1Vxg53f5BpV4tWhJyyjOtiNoADwuA6dPjAXKXDPfEgXwl/zBNg7VyJB8\n13IozGdV7SSJtPoUsuVZ3QZy+gtxVJgq/OlRp/bcDovGF9qxPR7WPSPUnBirIyCF\nkjk+ddFzDwkhdWjGv4MhQ8MxMhZdr9498Ok8NBVEjq5/f+cA0jmoKIZ7oSKk00kb\nqMiom8O04lPySy+wQPnm4RVjQZwW6Amg2REQoGm883QjYwHFb6pO8GfzJ+6Kt9au\nQf0kJJ1T2IDO9n69q3xHLeNCtHHK/VvcH50nggsU2rCVXBHg9tcMN0NDvJFnzDQz\nNkPB3beRtsrKUUS6ICB7WuXgtei/I+77XUlt9Vyf6ZgiGLf4m1fSBdZeTeLqMBK2\n-----END RSA PRIVATE KEY-----\n"
PrivKey = load_pem_private_key(rsa_key,b"popPdPd",default_backend())

class LaunchRequestHandler(AbstractRequestHandler):
     def can_handle(self, handler_input):
         # type: (HandlerInput) -> bool
         return is_request_type("LaunchRequest")(handler_input)

     def handle(self, handler_input):
         # type: (HandlerInput) -> Response
         #speech_text = "what you want to search for"
         speech_text = "Welcome to the mega secret skill. Do you want to start a secret conversation?"
         print ("launch intent recived")

        # handler_input.response_builder.speak(speech_text).set_card(
        #    SimpleCard("yes", speech_text)).set_should_end_session(
        #    False)
         handler_input.response_builder.speak(speech_text).set_should_end_session(
            False)
         return handler_input.response_builder.response

class OpenIntentHandler(AbstractRequestHandler):
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return is_intent_name("open_intent")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        speech_text = "Welcome to the mega secret skill. Do you want to start a secret conversation?"
        print(speech_text)
        handler_input.response_builder.speak(speech_text).set_card(
            SimpleCard("Welcome to the mega secret skill", speech_text)).set_should_end_session(
            False)
        return handler_input.response_builder.response

class SecretIntentHandler(AbstractRequestHandler):
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return is_intent_name("secret_chat")(handler_input)

    def handle(self, handler_input):
        global user_name
        global AES_engine
        # type: (HandlerInput) -> Response
	#print speech_text
        slots = handler_input.request_envelope.request.intent.slots
        name = slots['cmd']	
        user_name = name.value
        print(name)
        print (name.value)
        rtext = name.value 
        l = len(rtext)
        r = l % 8
        if( r != 0):
            for i in range(0,8-r):
                rtext = rtext + '='
        cypher_text = rtext.upper()
        print(cypher_text)
        cypher_text_bytes = base64.b32decode(cypher_text)
        print(cypher_text_bytes)
        plain_text = AES_engine.decrypt(cypher_text_bytes)
        speech_text_plain = "You said " + plain_text + " . what next"
        print('[1] plain text ',plain_text)
        speech_text_cipher = AES_engine.encrypt(speech_text_plain)
        print('[2]')
        coded_cypher = base64.b32encode(speech_text_cipher)
        print('[3]')
        speech_text = coded_cypher.decode().replace('=','').lower()
        print('[4] speech text ',speech_text)
#        handler_input.response_builder.speak(speech_text).set_card(
#            SimpleCard("sure", speech_text)).set_should_end_session(
#            True)
        handler_input.response_builder.speak(speech_text).set_should_end_session(
            False)
        return handler_input.response_builder.response

class KeyIntentHandler(AbstractRequestHandler):
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return is_intent_name("key_intent")(handler_input)

    def handle(self, handler_input):
        global user_name
        global AES_engine
        # type: (HandlerInput) -> Response
	#print speech_text
        slots = handler_input.request_envelope.request.intent.slots
        name = slots['cmd']	
        sym_key_cyphered = name.value
        print(name)
        sym_key_cyphered = sym_key_cyphered.upper()
        sym_key_cyphered = sym_key_cyphered + "==="
        print (sym_key_cyphered)
        sym_key_cyphered_bytes = base64.b32decode(sym_key_cyphered)
        print('after')
        sym_key_plain = PrivKey.decrypt(
            sym_key_cyphered_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
        )
        print(str(sym_key_plain))
        AES_engine.key = sym_key_plain
        speech_text = "A secure connection has stablished. Tell me some thing"
#        handler_input.response_builder.speak(speech_text).set_card(
#            SimpleCard("sure", speech_text)).set_should_end_session(
#            True)
        handler_input.response_builder.speak(speech_text).set_should_end_session(
            False)
        return handler_input.response_builder.response
class FriendIntentHandler(AbstractRequestHandler):
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return is_intent_name("friend_intent")(handler_input)

    def handle(self, handler_input):
        global friend_name
        # type: (HandlerInput) -> Response
	#print speech_text
        slots = handler_input.request_envelope.request.intent.slots
        name = slots['name']	
        friend_name = name.value
        print(name)
        print (name.value)
        speech_text =  user_name + " Say hello to " + name.value + " . our conversation started"
#        handler_input.response_builder.speak(speech_text).set_card(
#            SimpleCard("sure", speech_text)).set_should_end_session(
#            True)
        handler_input.response_builder.speak(speech_text).set_should_end_session(
            False)
        return handler_input.response_builder.response
class GoodByeIntentHandler(AbstractRequestHandler):
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return is_intent_name("goodbye_intent")(handler_input)

    def handle(self, handler_input):
        global user_name
        # type: (HandlerInput) -> Response
	#print speech_text
        speech_text = "Goodbye " + user_name
        user_name = "Bob"
#        handler_input.response_builder.speak(speech_text).set_card(
#            SimpleCard("sure", speech_text)).set_should_end_session(
#            True)
        handler_input.response_builder.speak(speech_text).set_should_end_session(
            True)
        return handler_input.response_builder.response

class HelpIntentHandler(AbstractRequestHandler):
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return is_intent_name("AMAZON.HelpIntent")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        speech_text = "You can say hello to me!"

        handler_input.response_builder.speak(speech_text).ask(speech_text).set_card(
            SimpleCard("Hello World", speech_text))
        return handler_input.response_builder.response

class CancelOrStopIntentHandler(AbstractRequestHandler):
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return is_intent_name("AMAZON.CancelIntent")(handler_input) or is_intent_name("AMAZON.StopIntent")(handler_input)

    def handle(self, handler_input):
        global user_name
        global friend_name
        # type: (HandlerInput) -> Response
        #speech_text = "Goodbye! " + user_name + ' and ' + friend_name
        speech_text = "BYE"
        user_name = 'bob'
        friend_name = 'alice'

        handler_input.response_builder.speak(speech_text).set_card(
            SimpleCard("Hello World", speech_text))
        return handler_input.response_builder.response

class SessionEndedRequestHandler(AbstractRequestHandler):
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return is_request_type("SessionEndedRequest")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        # any cleanup logic goes here

        return handler_input.response_builder.response

class FallbackIntentHandler(AbstractRequestHandler):
    """AMAZON.FallbackIntent is only available in en-US locale.
    This handler will not be triggered except in that locale,
    so it is safe to deploy on any locale.
    """
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return is_intent_name("AMAZON.FallbackIntent")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        speech_text = (
            "The Hello World skill can't help you with that.  "
            "Try saying hello!")
        reprompt = "You can say hello!!"
        handler_input.response_builder.speak(speech_text).ask(reprompt)
        return handler_input.response_builder.response

from ask_sdk_core.dispatch_components import AbstractExceptionHandler

class AllExceptionHandler(AbstractExceptionHandler):

    def can_handle(self, handler_input, exception):
        # type: (HandlerInput, Exception) -> bool
        return True

    def handle(self, handler_input, exception):
        # type: (HandlerInput, Exception) -> Response
        # Log the exception in CloudWatch Logs
        print(exception)

        speech = "Sorry, I didn't get it. Can you please say it again!!"
        handler_input.response_builder.speak(speech).ask(speech)
        return handler_input.response_builder.response

@app.route('/', methods=['POST'])
def post():
    """
    Process the request as following :
    - Get the input request JSON
    - Deserialize it to Request Envelope
    - Verify the request was sent by Alexa
    - Invoke the skill
    - Return the serialized response
    """
    content = request.json
    request_envelope = skill_obj.serializer.deserialize(
        payload=json.dumps(content), obj_type=RequestEnvelope)
#Mohammad
    print(' Mohammmad: a post recieved from: ')
    print( request_envelope.context.system.application.application_id)
    # https://developer.amazon.com/docs/custom-skills/host-a-custom-skill-as-a-web-service.html#verifying-that-the-request-was-sent-by-alexa
    # For eg, check if Skill ID matches
    if (request_envelope.context.system.application.application_id
            != "amzn1.ask.skill.9849b9a8-3b8c-4de4-bf5c-deb2d197e379"):
        print("Skill called with incorrect skill ID")
        return {}

    response_envelope = skill_obj.invoke(
        request_envelope=request_envelope, context=None)
    return jsonify(skill_obj.serializer.serialize(response_envelope))



sb.add_request_handler(LaunchRequestHandler())
#sb.add_request_handler(HelloWorldIntentHandler())
sb.add_request_handler(OpenIntentHandler())
#sb.add_request_handler(TranslateIntentHandler())
sb.add_request_handler(SecretIntentHandler())
sb.add_request_handler(KeyIntentHandler())
sb.add_request_handler(FriendIntentHandler())
sb.add_request_handler(GoodByeIntentHandler())
sb.add_request_handler(HelpIntentHandler())
sb.add_request_handler(CancelOrStopIntentHandler())
sb.add_request_handler(FallbackIntentHandler())
sb.add_request_handler(SessionEndedRequestHandler())

sb.add_exception_handler(AllExceptionHandler())


if __name__ == '__main__':
    app.run(debug=True, host = '0.0.0.0')

skill_obj = sb.create()
