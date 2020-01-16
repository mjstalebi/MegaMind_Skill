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

class LaunchRequestHandler(AbstractRequestHandler):
     def can_handle(self, handler_input):
         # type: (HandlerInput) -> bool
         return is_request_type("LaunchRequest")(handler_input)

     def handle(self, handler_input):
         # type: (HandlerInput) -> Response
         #speech_text = "what you want to search for"
         speech_text = "yes"
         print "launch intent recived"

        # handler_input.response_builder.speak(speech_text).set_card(
        #    SimpleCard("yes", speech_text)).set_should_end_session(
        #    False)
         handler_input.response_builder.speak(speech_text).set_should_end_session(
            False)
         return handler_input.response_builder.response

class HelloWorldIntentHandler(AbstractRequestHandler):
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return is_intent_name("HelloWorldIntent")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        speech_text = "Hello World from Javad"
	print speech_text
        handler_input.response_builder.speak(speech_text).set_card(
            SimpleCard("Hello World from Javad", speech_text)).set_should_end_session(
            False)
        return handler_input.response_builder.response

class TranslateIntentHandler(AbstractRequestHandler):
    def can_handle(self, handler_input):
        # type: (HandlerInput) -> bool
        return is_intent_name("translate")(handler_input)

    def handle(self, handler_input):
        # type: (HandlerInput) -> Response
        speech_text = "sure"
	#print speech_text
        slots = handler_input.request_envelope.request.intent.slots
        phrase = slots['phrase']
        print phrase.value
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
        # type: (HandlerInput) -> Response
        speech_text = "Goodbye!"

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
            != "amzn1.ask.skill.ff472ce1-6ec7-43b3-bc4a-27ee70be5fbd"):
        print("Skill called with incorrect skill ID")
        return {}

    response_envelope = skill_obj.invoke(
        request_envelope=request_envelope, context=None)
    return jsonify(skill_obj.serializer.serialize(response_envelope))



sb.add_request_handler(LaunchRequestHandler())
sb.add_request_handler(HelloWorldIntentHandler())
sb.add_request_handler(TranslateIntentHandler())
sb.add_request_handler(HelpIntentHandler())
sb.add_request_handler(CancelOrStopIntentHandler())
sb.add_request_handler(FallbackIntentHandler())
sb.add_request_handler(SessionEndedRequestHandler())

sb.add_exception_handler(AllExceptionHandler())


if __name__ == '__main__':
    app.run(debug=True, host = '0.0.0.0')

skill_obj = sb.create()
