class SafeHeaders:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)
        response['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        response['X-Content-Type-Options'] = 'nosniff'
        if request.path.startswith('/manage/'):
            response['Cache-Control'] = 'no-store'
        return response
