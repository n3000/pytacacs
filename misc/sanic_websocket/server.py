import json
import os

import jinja2
import aioredis
from sanic import Sanic
from sanic_jinja2 import SanicJinja2

STATIC_DIR = os.path.join(os.path.dirname(__file__), 'static')
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')

app = Sanic()
app.static('/static', './static')
jinja = SanicJinja2(app, loader=jinja2.FileSystemLoader(TEMPLATE_DIR), enable_async=True)


@app.route("/")
async def index(request):
    return await jinja.render_async('index.html', request)


@app.websocket('/ws')
async def feed(request, ws):
    res = await app.config.redis.subscribe('tacacs_accounting:1')
    channel = res[0]

    while await channel.wait_message():
        data = await channel.get_json()
        print("Got Message: {0}".format(data))

        if 'cmd' not in data['args'] and data['args'].get('service', '') == 'shell':
            # Its a login/out
            if 'TAC_PLUS_ACCT_FLAG_START' in data['flags']:
                msg = 'Connected'
            else:
                msg = 'Disconnected'
        elif 'cmd' in data['args']:
            msg = 'Ran command "{0}"'.format(data['args']['cmd'])
        else:
            msg = str(data['args'])

        result = {
            'network_device': '{0} ({1})'.format(data['source_name'], data['source_addr']),
            'remote_address': data['remote_address'],
            'user': data['user'],
            'task_id': data['args']['task_id'],
            'msg': msg
        }

        await ws.send(json.dumps(result))


@app.listener('before_server_start')
async def setup_db(app, loop):
    app.config.redis = await aioredis.create_redis('redis://localhost:6379')


@app.listener('after_server_stop')
async def close_db(app, loop):
    app.config.redis.close()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)
