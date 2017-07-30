from werkzeug.contrib.profiler import ProfilerMiddleware
from run import app
app.wsgi_app = ProfilerMiddleware(app.wsgi_app, restrictions = [10])
app.run(debug=True)