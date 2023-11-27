from abc import ABC, abstractmethod, abstractproperty
from typing import Any
import json
import hashlib
import datetime
import logging
import random
from scoring import *
from optparse import OptionParser
from http.server import BaseHTTPRequestHandler, HTTPServer

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
UNAUTHORIZED = 401
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


def get_score_test(store, phone, email, birthday=None, gender=None, first_name=None, last_name=None):
    score = 0
    if phone:
        score += 1.5
    if email:
        score += 1.5
    if birthday and gender:
        score += 1.5
    if first_name and last_name:
        score += 0.5
    return score


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode()).hexdigest()
    else:
        digest = hashlib.sha512((request.account + request.login + SALT).encode()).hexdigest()
    if digest == request.token:
        return True
    return False


def get_interests_test(store, cid):
    interests = ["cars", "pets", "travel", "hi-tech", "sport", "music", "books", "tv", "cinema", "geek", "otus"]
    return random.sample(interests, 2)


class TemplateField(ABC):
    def __init__(self, *args, **kwargs):
        self.field_name = None
        self.required = kwargs.get('required', True)
        self.nullable = kwargs.get('nullable', True)

    def __get__(self, obj, cls):
        return self

    def __set__(self, obj, params):
        value = None
        self.is_filled= False
        self.is_valid = False
        self.is_declared = False

        if self.field_name in params:
            self.is_declared = True
            value = params[self.field_name]
            if not(value is None or (hasattr(value, '__len__') and len(value) == 0)):
                self.is_filled = True
            else:
                if not self.nullable:
                    logging.error(f'[{self.field_name}] is null')

        else:
            if self.required:
                logging.error(f'[{self.field_name}] not declared')
        if self.set_value(value):
            self.is_valid = True
        else:
            logging.error(f'[{self.field_name}] not valid value')

    @property
    def correct(self):
        return self.is_valid and (self.is_declared or not self.required) and (self.is_filled or self.nullable)

    def get_not_valid_reason(self) -> str:
        if not self.correct:
            if not self.is_declared and self.required:
                return 'not_declare'
            elif not(self.is_filled or self.nullable):
                return 'null'
            else:
                return 'not_valid'
        return 'ok'

    def __str__(self):
        return self.value if bool(self) else ''

    def __add__(self, other):
        return self.value + other.value

    @abstractmethod
    def set_value(self, value):
        pass


    def __and__(self, other):
        return bool(self) & bool(other)

    def __or__(self, other):
        return bool(self) | bool(other)

    def __rand__(self, other):
        return bool(self) & bool(other)

    def __ror__(self, other):
        return bool(self) | bool(other)

    def __eq__(self, other):
        return str(self) == str(other)

    def __bool__(self):
        return self.correct

    def __set_name__(self, owner, name):
        self.field_name = name
        owner.fields_list.update(name)


class CharField(TemplateField):
    """
        contains simple text fields
        return True if value is valid, False otherwise
    """
    def __init__(self, *args, **kwargs):
        self.value = ''
        super().__init__(*args, **kwargs)

    def set_value(self, value) -> bool:
        self.value = value
        return True


class ClientIDsField(TemplateField):
    """
        contains client id fields (in tuple)
        return True if value is valid, False otherwise
    """
    def __init__(self, *args, **kwargs):
        self.value = list()
        super().__init__(*args, **kwargs)

    def set_value(self, value) -> bool:
        if hasattr(value, '__iter__'):
            self.value = (*value,)
        else:
            self.value = (value,)
        return True

    def __iter__(self):
        return self.value.__iter__()



class ArgumentsField(TemplateField):
    """
        contains arguments dictionary
        return True if value is valid, False otherwise
    """

    def __init__(self, *args, **kwargs):
        self.value = dict()
        super().__init__(*args, **kwargs)

    def set_value(self, value):
        self.value = value if value is not None else dict()
        return True

    def __str__(self):
        return self.value.__str__()

    def __contains__(self, item):
        return item in self.value

    def __setitem__(self, key, value):
        self.value[key] = value

    def __getitem__(self, item):
        return self.value[item]

    def __len__(self):
        return len(self.value)


class EmailField(TemplateField):
    """
           contains email fields.
           set method checks for "@" in string
           return True if value is valid, False otherwise
    """
    def __init__(self, *args, **kwargs):
        self.value = None
        super().__init__(*args, **kwargs)

    def set_value(self, value):
        if value is not None:
            if isinstance(value, str) and '@' in value:
                self.value = value
            else:
                return False
        return True


class PhoneField(TemplateField):
    """
        contains phone number
    """
    def __init__(self, *args, **kwargs):
        self.value = None
        super().__init__(*args, **kwargs)

    def set_value(self, value):
        if not (value.isdigit()
                and value[0] == '7'
                and len(value) == 11):
            return True
        else:
            return False


class DateField(TemplateField):
    """
        contain and date field.
    """

    def set_value(self, value):
        try:
            self.value = datetime.datetime.strptime(value, '%d.%m.%Y')

        except ValueError as e:
            self.incorrect_flag = True
            self.syntax_violation = True
            logging.error('date format error')

    def __str__(self):
        return datetime.datetime.strftime(self.value, '%d.%m.%Y')


class BirthDayField(DateField):
    """
        contain and check person birthday.
    """
    def set_value(self, value):
        super().set_value(value)
        if self.value:
            today = datetime.date.today()
            age = today.year - self.value.year - (today.timetuple().tm_yday < self.value.timetuple().tm_yday)
            if 70 >= age > 0:
                self.value = self.value
            else:
                self.incorrect_flag = True
                self.syntax_violation = True
                logging.error('age period [0..70] exceed')

    def __str__(self):
        return datetime.datetime.strftime(self.value, '%d.%m.%Y')


class GenderField(TemplateField):
    """
        contain and check person birthday.
    """
    def set_value(self, value):
        if value in GENDERS:
            self.value = value
        else:
            logging.error('gender encoding format error')


class TemplateRequest(ABC):
    context = None
    store = None

    def __init__(self, decorated_function):
        self.call = decorated_function

    def __call__(self, request, ctx, store):
        self.context = ctx
        self.store = store
        response, code = self.call(request, ctx, store)
        if code is None and self.is_processed:
            for field_name in self.fields_list:
                setattr(self, field_name,
                        self.arguments if isinstance(self.call, TemplateRequest) else request['body'])
            if self.is_correct_arguments:
                response, code = self.process_function()
            else:
                response, code = self.get_response_error()
        return response, code


    def __contains__(self, method_name):
        return str(method_name) in self.support_methods

    @property
    @abstractmethod
    def is_correct_arguments(self):
        pass

    @property
    @abstractmethod
    def is_processed(self):
        pass

    @abstractmethod
    def process_function(self):
        pass

    @abstractmethod
    def get_response_error(self):
        pass

    def __getattr__(self, name):
        return getattr(self.call, name)


class MethodRequest(TemplateRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)
    fields = dict()

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN

    @property
    def is_processed(self):
        return True

    @property
    def is_correct_arguments(self):
        for field_name in self.fields:
            if field_name['incorrect_flag']:
                return False
        return True

    def process_function(self):
        if check_auth(self):
            return 'Forbidden', FORBIDDEN

    def get_response_error(self):
        response = list()
        for field_name in self.fields:
            if field_name['incorrect_flag']:
                response.append(field_name)
        return response




class OnlineScoreRequest(TemplateRequest):
    fields_list = []
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self, *args, **kwargs):
        self.support_methods = {'online_score'}
        super().__init__(*args, **kwargs)

    @property
    def is_processed(self):
        return self.method in self


class ClientsInterestsRequest(TemplateRequest):
    fields_list = []
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def __init__(self, *args, **kwargs):
        self.support_methods = {'clients_interests'}
        super().__init__(*args, **kwargs)

    @property
    def is_processed(self):
        return self.method in self


class TerminalRequest(TemplateRequest):

    def wrapper(self, request, ctx, store):
        response, code = self.call(request, ctx, store)
        if code is None:
            # return json.dumps({
            #     'errors': ERRORS[INVALID_REQUEST],
            #     'code':INVALID_REQUEST})
            return response, code
        else:
            response_type = 'response' if code == OK else 'error'
            # return json.dumps({
            #     response_type: response,
            #     'code': code})
            return response, code

    @property
    def is_processed(self):
        return True


def pipe_get_score(request, ctx, store):
    if not ((request.first_name & request.last_name) | (request.email & request.phone) |
            (request.gender & request.birthday)):
        all_fields = (request.first_name, request.last_name,
                      request.email, request.phone,
                      request.gender, request.birthday)

        return [field.field_name for field in all_fields if not field], 4226

    try:
        score = get_score(store, request.phone.value, request.email.value, request.birthday.value,
                          request.gender.value, request.first_name.value, request.last_name.value)
        return {"score": score}, OK
    except:
        return None, INTERNAL_ERROR


def pipe_get_interests(request, ctx, store):
    result_interests_dict = dict()
    for client_id in request.client_ids:
        interests = get_interests(store, client_id)
        result_interests_dict.update([(str(client_id), interests)])
    return result_interests_dict, OK


@TerminalRequest
@ClientsInterestsRequest(target_handler=pipe_get_interests)
@OnlineScoreRequest(target_handler=pipe_get_score)
@MethodRequest
def method_handler(request, ctx, store):
    response, code = None, None
    return response, code


arg = dict(body={'method': 'online_score',
                 'account': '123001234',
                 'login': 'freebsd',
                 'token': hashlib.sha512(('123001234' + 'freebsd' + SALT).encode()).hexdigest(),
                 'arguments': {"phone":"79175002040", "email": "stupnikov@otus.ru", "gender":1, "birthday": "26.10.1960", "first_name": "stanislav", "last_name1": "stulenkov"}
                 })
#
# arg1 = {'method': 'clients_interests',
#         'account': '123001234',
#         'login': 'freebsd',
#         'token': hashlib.sha512(('123001234' + 'freebsd' + SALT).encode()).hexdigest(),
#         'arguments': '{"client_ids": [1, 2], "date": "19.07.2017"}'
#         }
#
# arg2= {'method': 'online_score',
#        'account': '123001234',
#        'login': 'freebsd',
#        'token': hashlib.sha512(('123001234' + 'freebsd' + SALT).encode()).hexdigest(),
#        'arguments': '{"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "26.10.1960", "first_name": "stanislav", "last_name1": "stulenkov"}'
#        }
# #
print(method_handler(arg, None, 123))
# print('-' * 50)
# print(method_handler.method)
# print(method_handler.login)
# print(method_handler.account)
# print(method_handler.arguments)
# print('phone:{}'.format(method_handler.phone))
# print('mail:{}'.format(method_handler.email))

# auth_str = '123001234' + 'freebsd' + SALT
# digest = hashlib.sha512(auth_str.encode()).hexdigest()
# print('token:{}'.format(digest))
# print(method_handler.check_auth)
# # print(method_handler.phone.value)
# print(method_handler.first_name)
# print(method_handler.email)
# print(method_handler.birthday)
# print('gender:{}'.format(method_handler.gender))
#
# print(method_handler.last_name.value)


#   print('method:{}'.format(request['method']))
#     print('args: {}'.format(request['args']))
