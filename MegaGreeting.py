from flask import Flask, request, jsonify
import json

from ask_sdk_core.skill_builder import SkillBuilder
from ask_sdk_core.dispatch_components import AbstractRequestHandler
from ask_sdk_core.utils import is_request_type, is_intent_name
from ask_sdk_core.handler_input import HandlerInput
from ask_sdk_model.ui import SimpleCard
from ask_sdk_model import Response, RequestEnvelope

app = Flask(__name__)
sb = SkillBuilder()

user_name = "Bob"
friend_name = "Alice"
class LaunchRequestHandler(AbstractRequestHandler):
     def can_handle(self, handler_input):
         # type: (HandlerInput) -> bool
         return is_request_type("LaunchRequest")(handler_input)

     def handle(self, handler_input):
         # type: (HandlerInput) -> Response
         #speech_text = "what you want to search for"
         speech_text = "Hello from Mega greeting. What is your name?"
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
        speech_text = "Hello from Mega Greeting. What is your name?"
        print(speech_text)
        handler_input.response_builder.speak(speech_text).set_card(
            SimpleCard("Hello World from Mega Greetign what is your name", speech_text)).set_should_end_session(
            False)
        return handler_input.response_builder.response

class NameIntentHandler(AbstractRequestHandler):
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return is_intent_name("name_intent")(handler_input)

    def handle(self, handler_input):
        global user_name
        # type: (HandlerInput) -> Response
	#print speech_text
        slots = handler_input.request_envelope.request.intent.slots
        name = slots['name']	
        user_name = name.value
        print(name)
        print (name.value)
        speech_text = "Hello " + name.value + " . What is your friend's name?"
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
        speech_text = "Goodbye! " + user_name + ' and ' + friend_name
        #speech_text = "fkasjhfefnnjhfejhaefeefaef"
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
            != "amzn1.ask.skill.0229175e-49e9-488f-9920-8dfe0dbdad4a"):
        print("Skill called with incorrect skill ID")
        return {}

    response_envelope = skill_obj.invoke(
        request_envelope=request_envelope, context=None)
    return jsonify(skill_obj.serializer.serialize(response_envelope))



sb.add_request_handler(LaunchRequestHandler())
#sb.add_request_handler(HelloWorldIntentHandler())
sb.add_request_handler(OpenIntentHandler())
#sb.add_request_handler(TranslateIntentHandler())
sb.add_request_handler(NameIntentHandler())
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
