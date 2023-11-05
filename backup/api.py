from abc import ABC, abstractmethod, abstractproperty
from typing import Any
import json
import hashlib
import datetime
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


class TemplateRequest(ABC):
    def __init__(self, *args, **kwargs):
        if len(args) > 0 and callable(args[0]):
            self.current_wrapper = self.wrapper
            self.call = args[0]
            self.target_handler = self.target_handler_stub
        else:
            self.target_handler = (kwargs.get('target_handler', check_auth))
            self.current_wrapper = self.decorator

    def decorator(self, function):
        self.call = function
        self.current_wrapper = self.wrapper
        return self

    def wrapper(self, request, ctx, store):
        response, code = self.call(request, ctx, store)
        if code is None and self.is_processed:
            try:
                for field_name in type(self).fields_list:
                    setattr(self, field_name, self.arguments if isinstance(self.call, TemplateRequest) else request)
                status = self.target_handler(self, ctx, store)
                if isinstance(status, tuple):
                    return status
                else:
                    return (None, None) if status else (None, UNAUTHORIZED)
            except:
                response = None
                code = INVALID_REQUEST
        return response, code

    def target_handler_stub(self, request, ctx, store):
        return check_auth(request)

    def __contains__(self, method_name):
        return str(method_name) in self.support_methods

    def __call__(self, *args, **kwargs):
        return self.current_wrapper(*args, **kwargs)

    @property
    @abstractmethod
    def is_processed(self):
        pass

    def __call__(self, *args, **kwargs):
        return self.current_wrapper(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self.call, name)


class TemplateField(ABC):
    def __init__(self, *args, **kwargs):
        self.value = None
        self.field_name = None
        self.incorrect_flag = False
        self.required = kwargs.get('required', True)
        self.nullable = kwargs.get('nullable', True)

    def __get__(self, obj, cls):
        return self

    def __set__(self, obj, value):
        if self.field_name in value:
            type(self).set_value(self, value[self.field_name])
            if self.value is None and not self.nullable:
                raise ValueError(f'[{self.field_name}] should not be None')
        else:
            if self.required:
                raise ValueError(f'[{self.field_name}] field should be define')

    def __str__(self):
        return self.value if bool(self) else ''

    def __add__(self, other):
        return self.value + other.value

    @abstractmethod
    def set_value(self, value):
        pass

    def __and__(self, other):
        return (self.value is not None) & bool(other)

    def __or__(self, other):
        return (self.value is not None) | bool(other)

    def __rand__(self, other):
        return (self.value is not None) & bool(other)

    def __ror__(self, other):
        return (self.value is not None) | bool(other)

    def __eq__(self, other):
        return str(self) == str(other)

    def __bool__(self):
        return self.value is not None

    def __set_name__(self, owner, name):
        self.field_name = name
        owner.fields_list.append(name)


class CharField(TemplateField):
    """
        contains simple text fields
    """

    def set_value(self, value) -> Any:
        self.value = value


class ClientIDsField(TemplateField):
    """
        contains client id fields (as simple text)
    """

    def set_value(self, value) -> Any:
        self.value = tuple(value)

    def __iter__(self):
        return self.value.__iter__()

    def __str__(self):
        return self.value.__str__()


class ArgumentsField(TemplateField):
    """
        contains arguments dictionary
    """

    def set_value(self, value):
        try:
            self.value = json.loads(value)
        except ValueError(f'error in arguments json:{value}') as e:
            self.incorrect_flag = True
            raise ValueError from e

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
    """

    def set_value(self, value):
        if '@' not in value:
            self.incorrect_flag = True
            raise ValueError(f'[{self.field_name}] incorrect email format')
        else:
            self.value = value


class PhoneField(TemplateField):
    """
        contains phone number
    """

    def set_value(self, value):
        if not (value.isdigit()
                and value[0] == '7'
                and len(value) == 11):
            self.incorrect_flag = True
            raise ValueError(f'[{self.field_name}] incorrect phone number format')
        else:
            self.value = value


class DateField(TemplateField):
    """
        contain and date field.
    """

    def set_value(self, value):
        try:
            date = datetime.datetime.strptime(value, '%d.%m.%Y')

        except ValueError as e:
            self.incorrect_flag = True
            raise ValueError from e

    def __str__(self):
        return datetime.datetime.strftime(self.value, '%d.%m.%Y')


class BirthDayField(DateField):
    """
        contain and check person birthday.
    """

    def set_value(self, value):
        try:
            birthday = datetime.datetime.strptime(value, '%d.%m.%Y')
            today = datetime.date.today()
            age = today.year - birthday.year - (today.timetuple().tm_yday < birthday.timetuple().tm_yday)
            if 70 >= age > 0:
                self.value = birthday
            else:
                raise ValueError(f'age={age} out of range [0..70]')
        except ValueError as e:
            self.incorrect_flag = True
            raise ValueError from e

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
            raise ValueError(f'[{self.field_name}] incorrect gender decoding format')


class MethodRequest(TemplateRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)
    fields_list = []

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN

    @property
    def is_processed(self):
        return True


class TerminalRequest(TemplateRequest):

    def wrapper(self, request, ctx, store):
        response, code = self.call(request, ctx, store)
        if code is None:
            # return json.dumps({
            #     'errors': ERRORS[INVALID_REQUEST],
            #     'code':INVALID_REQUEST})
            return  response, code
        else:
            response_type = 'response' if code == OK else 'error'
            # return json.dumps({
            #     response_type: response,
            #     'code': code})
            return response, code


    @property
    def is_processed(self):
        return True


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


class OnlineScoreRequest(TemplateRequest):
    fields_list = []
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=True, nullable=True)

    def __init__(self, *args, **kwargs):
        self.support_methods = {'online_score'}
        super().__init__(*args, **kwargs)

    @property
    def is_processed(self):
        return self.method in self


def pipe_get_score(request, ctx, store):
    if not ((request.first_name | request.last_name) & (request.email | request.phone) &
            (request.gender | request.birthday)):
        all_fields = (request.first_name, request.last_name,
                      request.email, request.phone,
                      request.gender & request.birthday)

        return  [field.field_name for field in all_fields if not field], INVALID_REQUEST

    try:
        score = get_score(store, request.phone.value, request.email.value, request.birthday.value,
                          request.gender.value, request.first_name.value, request.last_name.value)
        return score, OK
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

arg = {'method1': 'online_score',
       'account1': '123001234',
       'login1': 'freebsd',
       'token1': hashlib.sha512(('123001234' + 'freebsd' + SALT).encode()).hexdigest(),
       'arguments1': '{"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "26.10.1960", "first_name": "stanislav", "last_name1": "stulenkov"}'
       }

arg1 = {'method': 'clients_interests',
        'account': '123001234',
        'login': 'freebsd',
        'token': hashlib.sha512(('123001234' + 'freebsd' + SALT).encode()).hexdigest(),
        'arguments': '{"client_ids": [1, 2], "date": "19.07.2017"}'
        }

print(method_handler(arg, None, 123))
print('-' * 50)
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
