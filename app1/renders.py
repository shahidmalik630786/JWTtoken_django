from rest_framework import renderers
import json

class UserRenderer(renderers.JSONRenderer):
    charset = 'utf-8'  # Corrected typo: 'chartset' to 'charset'

    def render(self, data, accepted_media_type=None, renderer_context=None):
        if "ErrorDetail" in data:
            response = json.dumps({'errors': data})
            print(response,"&&&&&&&&&")
        else:
            response = json.dumps(data)
            print(response,"########")

        return response
