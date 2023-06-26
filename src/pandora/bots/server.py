# -*- coding: utf-8 -*-

import logging
import json
import pickle
import threading
import base64
from datetime import timedelta
from os.path import join, abspath, dirname

from flask import Flask, jsonify, make_response, request, Response, render_template
from flask_cors import CORS
from waitress import serve
from werkzeug.exceptions import default_exceptions
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.serving import WSGIRequestHandler

from .. import __version__
from ..exts.hooks import hook_logging
from ..openai.api import API


class ChatBot:
    __default_ip = '127.0.0.1'
    __default_port = 8008

    def __init__(self, chatgpt, debug=False, sentry=False):
        self.chatgpt = chatgpt
        self.debug = debug
        self.sentry = sentry
        self.log_level = logging.DEBUG if debug else logging.WARN

        hook_logging(level=self.log_level, format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s')
        self.logger = logging.getLogger('waitress')

    def run(self, bind_str, threads=8):
        host, port = self.__parse_bind(bind_str)

        resource_path = abspath(join(dirname(__file__), '..', 'flask'))
        app = Flask(__name__, static_url_path='',
                    static_folder=join(resource_path, 'static'),
                    template_folder=join(resource_path, 'templates'))
        app.wsgi_app = ProxyFix(app.wsgi_app, x_port=1)
        app.after_request(self.__after_request)

        CORS(app, resources={r'/api/*': {'supports_credentials': True, 'expose_headers': [
            'Content-Type',
            'Authorization',
            'X-Requested-With',
            'Accept',
            'Origin',
            'Access-Control-Request-Method',
            'Access-Control-Request-Headers',
            'Content-Disposition',
        ], 'max_age': 600}})

        for ex in default_exceptions:
            app.register_error_handler(ex, self.__handle_error)

        app.route('/api/models')(self.list_models)
        app.route('/api/conversations')(self.list_conversations)
        app.route('/api/conversations', methods=['DELETE'])(self.clear_conversations)
        app.route('/api/conversation/<conversation_id>')(self.get_conversation)
        app.route('/api/conversation/<conversation_id>', methods=['DELETE'])(self.del_conversation)
        app.route('/api/conversation/<conversation_id>', methods=['PATCH'])(self.set_conversation_title)
        app.route('/api/conversation/gen_title/<conversation_id>', methods=['POST'])(self.gen_conversation_title)
        app.route('/api/conversation/talk', methods=['POST'])(self.talk)
        app.route('/api/conversation/regenerate', methods=['POST'])(self.regenerate)
        app.route('/api/conversation/goon', methods=['POST'])(self.goon)

        app.route('/api/auth/session')(self.session)
        app.route('/api/accounts/check')(self.check)
        app.route('/_next/data/olf4sv64FWIcQ_zCGl90t/chat.json')(self.chat_info)

        app.route('/')(self.chat)
        app.route('/chat')(self.chat)
        app.route('/chat/<conversation_id>')(self.chat)

        if not self.debug:
            self.logger.warning('Serving on http://{}:{}'.format(host, port))

        self.logger.warning('333')
        try:
            self.logger.warning('首次加载start')
            with open('/data/user_items.pkl', 'rb') as f:
                self.user_items = pickle.load(f)
        except FileNotFoundError:
            self.logger.warning('No existing file found. A new file will be created.')
        self.logger.warning('首次加载end')
        self.logger.warning('2222')
        # self.user_items = {'user123': ['1de4e8af-846e-4c9d-b660-bf069d5e6a67', 'a744d303-034d-4bbd-be62-395767a32d64']}
        self.timer = threading.Timer(5.0, self.save_user_items)
        self.timer.start()


        self.logger.warning('444')

        WSGIRequestHandler.protocol_version = 'HTTP/1.1'
        serve(app, host=host, port=port, ident=None, threads=threads)

    @staticmethod
    def __after_request(resp):
        resp.headers['X-Server'] = 'dashao_m/{}'.format(__version__)

        return resp

    def __parse_bind(self, bind_str):
        sections = bind_str.split(':', 2)
        if len(sections) < 2:
            try:
                port = int(sections[0])
                return self.__default_ip, port
            except ValueError:
                return sections[0], self.__default_port

        return sections[0], int(sections[1])

    def __handle_error(self, e):
        self.logger.error(e)

        return make_response(jsonify({
            'code': e.code,
            'message': str(e.original_exception if self.debug and hasattr(e, 'original_exception') else e.name)
        }), 500)

    @staticmethod
    def __set_cookie(resp, token_key, max_age):
        resp.set_cookie('token-key', token_key, max_age=max_age, path='/', domain=None, httponly=True, samesite='Lax')

    @staticmethod
    def __get_token_key():
        return request.headers.get('X-Use-Token', request.cookies.get('token-key'))

    def chat(self, conversation_id=None):
        query = {'chatId': [conversation_id]} if conversation_id else {}

        token_key = request.args.get('token')
        rendered = render_template('chat.html',
                                   # pandora_base=request.url_root.strip('/'),
                                   pandora_base='http://gtp4.artifit.cn:9990',
                                   pandora_sentry=self.sentry,
                                   query=query
                                   )
        resp = make_response(rendered)

        if token_key:
            self.__set_cookie(resp, token_key, timedelta(days=30))

        return resp

    @staticmethod
    def session():
        ret = {
            'user': {
                'id': 'user-000000000000000000000000',
                'name': 'admin@openai.com',
                'email': 'admin@openai.com',
                'image': None,
                'picture': None,
                'groups': []
            },
            'expires': '2089-08-08T23:59:59.999Z',
            'accessToken': 'secret',
        }

        return jsonify(ret)

    @staticmethod
    def chat_info():
        ret = {
            'pageProps': {
                'user': {
                    'id': 'user-000000000000000000000000',
                    'name': 'admin@openai.com',
                    'email': 'admin@openai.com',
                    'image': None,
                    'picture': None,
                    'groups': []
                },
                'serviceStatus': {},
                'userCountry': 'US',
                'geoOk': True,
                'serviceAnnouncement': {
                    'paid': {},
                    'public': {}
                },
                'isUserInCanPayGroup': True
            },
            '__N_SSP': True
        }

        return jsonify(ret)

    @staticmethod
    def check():
        ret = {
            'account_plan': {
                'is_paid_subscription_active': True,
                'subscription_plan': 'chatgptplusplan',
                'account_user_role': 'account-owner',
                'was_paid_customer': True,
                'has_customer_object': True,
                'subscription_expires_at_timestamp': 3774355199
            },
            'user_country': 'US',
            'features': [
                'model_switcher',
                'dfw_message_feedback',
                'dfw_inline_message_regen_comparison',
                'model_preview',
                'system_message',
                'can_continue',
            ],
        }

        return jsonify(ret)

    def list_models(self):
        return self.__proxy_result(self.chatgpt.list_models(True, self.__get_token_key()))

    user_items = {'user123': ['1de4e8af-846e-4c9d-b660-bf069d5e6a67', 'a744d303-034d-4bbd-be62-395767a32d64']}
    timer = None

    def save_user_items(self):
        # self.logger.warning('开始保存start')
        with open('/data/user_items.pkl', 'wb') as f:
            pickle.dump(self.user_items, f)

        # 设置下一次调用
        self.timer = threading.Timer(30.0, self.save_user_items)
        self.timer.start()
        # self.logger.warning('开始保存end')

    # def load_user_items(self):
    #     try:
    #         self.logger.warning('首次加载start')
    #         with open('/opt/user_items.pkl', 'rb') as f:
    #             self.user_items = pickle.load(f)
    #     except FileNotFoundError:
    #         self.logger.warning('No existing file found. A new file will be created.')
    #     self.logger.warning('首次加载end')

    def list_conversations(self):
        user_id = 'user123'
        # auth_header = request.headers.get('Authorization')
        self.logger.warning(request.method)
        self.logger.warning(request.args)
        self.logger.warning(request.form)
        self.logger.warning(request.data)
        self.logger.warning(request.cookies)
        self.logger.warning(request.headers.get('User-Agent'))
        self.logger.warning(request.cookies)
        self.logger.warning(request.headers.get(request.headers.get('X-Use-Token', request.cookies.get('token-key'))))
        auth = request.authorization
        if auth is not None:
            self.logger.warning('Hello, {}!'.format(auth.username))
            user_id = auth.username
        else:
            self.logger.warning('null')
        # auth_info = base64.b64decode(auth_header[6:]).decode('utf-8')
        # username, password = auth_info.split(':', 1)
        # self.logger.warning('username:'+username)
        # self.logger.warning('password:'+password)

        if user_id in self.user_items:
            self.logger.warning(self.user_items[user_id])
        else:
            self.logger.warning(f'User ID {user_id} not found.')

        offset = request.args.get('offset', '0')
        limit = request.args.get('limit', '20')
        result = self.__proxy_result(self.chatgpt.list_conversations(offset, limit, True, self.__get_token_key()))
        # self.logger.warning(result.data)
        json_string = result.data.decode('utf-8')
        # self.logger.warning(json_string)
        data_dict = json.loads(json_string)
        # self.logger.warning(data_dict.items())
        # 从所有items里移除id不在'user123'的id里的items
        filtered_items = [item for item in data_dict['items'] if
                          (item['id'] in self.user_items.get(user_id, []) or item['title'] == 'New chat')]
        newChat_matching_ids = [item['id'] for item in data_dict['items'] if (item['title'] == 'New chat')]

        # 添加到user123的user_items列表中
        if user_id in self.user_items:
            self.user_items[user_id].extend(newChat_matching_ids)
        else:
            self.user_items[user_id] = newChat_matching_ids

        data_dict['items'] = filtered_items
        # self.logger.warning(result.data)
        # self.save_user_items
        # self.logger.warning(result.data)
        # 转换为JSON字符串
        data_dict_json_string = json.dumps(data_dict)

        # 转换为bytes对象
        result.data = data_dict_json_string.encode('utf-8')
        return result

    def get_conversation(self, conversation_id):
        return self.__proxy_result(self.chatgpt.get_conversation(conversation_id, True, self.__get_token_key()))

    def del_conversation(self, conversation_id):
        return self.__proxy_result(self.chatgpt.del_conversation(conversation_id, True, self.__get_token_key()))

    def clear_conversations(self):
        return self.__proxy_result(self.chatgpt.clear_conversations(True, self.__get_token_key()))

    def set_conversation_title(self, conversation_id):
        title = request.json['title']

        return self.__proxy_result(
            self.chatgpt.set_conversation_title(conversation_id, title, True, self.__get_token_key()))

    def gen_conversation_title(self, conversation_id):
        payload = request.json
        model = payload['model']
        message_id = payload['message_id']

        return self.__proxy_result(
            self.chatgpt.gen_conversation_title(conversation_id, model, message_id, True, self.__get_token_key()))

    def talk(self):
        payload = request.json
        prompt = payload['prompt']
        model = payload['model']
        message_id = payload['message_id']
        parent_message_id = payload['parent_message_id']
        conversation_id = payload.get('conversation_id')
        stream = payload.get('stream', True)

        return self.__process_stream(
            *self.chatgpt.talk(prompt, model, message_id, parent_message_id, conversation_id, stream,
                               self.__get_token_key()), stream)

    def goon(self):
        payload = request.json
        model = payload['model']
        parent_message_id = payload['parent_message_id']
        conversation_id = payload.get('conversation_id')
        stream = payload.get('stream', True)

        return self.__process_stream(
            *self.chatgpt.goon(model, parent_message_id, conversation_id, stream, self.__get_token_key()), stream)

    def regenerate(self):
        payload = request.json

        conversation_id = payload.get('conversation_id')
        if not conversation_id:
            return self.talk()

        prompt = payload['prompt']
        model = payload['model']
        message_id = payload['message_id']
        parent_message_id = payload['parent_message_id']
        stream = payload.get('stream', True)

        return self.__process_stream(
            *self.chatgpt.regenerate_reply(prompt, model, conversation_id, message_id, parent_message_id, stream,
                                           self.__get_token_key()), stream)

    @staticmethod
    def __process_stream(status, headers, generator, stream):
        if stream:
            return Response(API.wrap_stream_out(generator, status), mimetype=headers['Content-Type'], status=status)

        last_json = None
        for json in generator:
            last_json = json

        return make_response(last_json, status)

    @staticmethod
    def __proxy_result(remote_resp):
        resp = make_response(remote_resp.text)
        resp.content_type = remote_resp.headers['Content-Type']
        resp.status_code = remote_resp.status_code

        return resp
