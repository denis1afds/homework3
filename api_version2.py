from abc import ABC, abstractmethod
from typing import Any
import json
import hashlib
import datetime

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


def get_score(store, phone, email, birthday=None, gender=None, first_name=None, last_name=None):
    print('external handler')
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

class TemplateRequest(ABC):

    def __init__(self, *args, **kwargs):
        if len(args) > 0 and callable(args[0]):
            self.current_wrapper = self.wrapper
            self.call = args[0]
        else:

            self.target_handler = staticmethod(lambda store=self.store, first_name=self.first_name, last_name=self.last_name,
                                              email=self.email, phone=self.phone,
                                              birthday=self.birthday, gender=self.gender:
                                              eval(kwargs.get('target_handler', '0')))

            self.validate_rule = staticmethod(lambda first_name=self.first_name, last_name=self.last_name,
                                              email=self.email, phone=self.phone,
                                              birthday=self.birthday, gender=self.gender:
                                              eval(kwargs.get('validate_rule', 'True')))
            self.current_wrapper = self.decorator

    def decorator(self, function):
        self.call = function
        self.current_wrapper = self.wrapper
        return self

    def wrapper(self, request, ctx, store):
        response, code = self.call(request, ctx, store)
        if code is None and self.method in self:
            for field_name in type(self).fields_list:
                setattr(self, field_name, self.arguments)
            if self.validate_rule():
                self.store = store
                score = self.target_handler()
                return score, OK
            return None, BAD_REQUEST
        return  response, code

    def __contains__(self, method_name):
        return str(method_name) in self.support_methods

    def __call__(self, *args, **kwargs):
        return self.current_wrapper(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self.call, name)





class TemplateField(ABC):
    def __init__(self, *args, **kwargs):
        self.value = None
        self.field_name = None
        self.incorrect_flag = False
        self.required = kwargs['required']
        self.nullable = kwargs['nullable']

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


class BirthDayField(TemplateField):
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


class MethodRequest:
    fields_list = []
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    def __init__(self, function):
        self.method_request_object = self
        self.call = function

    def __call__(self, *args, **kwargs):
        for field_name in type(self).fields_list:
            setattr(self, field_name, args[0])
        request, code = self.call(*args, **kwargs)
        if not self.check_auth:
            code = UNAUTHORIZED
        return request, code

    @property
    def check_auth(self):
        if self.is_admin:
            auth_str = datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT
            digest = hashlib.sha512(auth_str.encode()).hexdigest()
        else:
            auth_str = self.account + self.login + SALT
            digest = hashlib.sha512(auth_str.encode()).hexdigest()

        auth_str = None
        print(digest,'\n',self.token)
        if digest == self.token:
            print('auth ok')
            return True

        return False

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN





class OnlineScoreRequest:
    fields_list = []
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self, *args, **kwargs):
        self.store = None
        self.support_methods = {'online_score'}
        self.target_handler = staticmethod(lambda: 1)
        self.validate_rule = staticmethod(lambda: True)

        if len(args) > 0 and callable(args[0]):
            self.current_wrapper = self.wrapper
            self.call = args[0]
        else:

            self.target_handler = staticmethod(lambda store=self.store, first_name=self.first_name, last_name=self.last_name,
                                              email=self.email, phone=self.phone,
                                              birthday=self.birthday, gender=self.gender:
                                              eval(kwargs.get('target_handler', '0')))

            self.validate_rule = staticmethod(lambda first_name=self.first_name, last_name=self.last_name,
                                              email=self.email, phone=self.phone,
                                              birthday=self.birthday, gender=self.gender:
                                              eval(kwargs.get('validate_rule', 'True')))
            self.current_wrapper = self.decorator

    def decorator(self, function):
        self.call = function
        self.current_wrapper = self.wrapper
        return self

    def wrapper(self, request, ctx, store):
        response, code = self.call(request, ctx, store)
        if code is None and self.method in self:
            for field_name in type(self).fields_list:
                setattr(self, field_name, self.arguments)
            if self.validate_rule():
                self.store = store
                score = self.target_handler()
                return score, OK
            return None, BAD_REQUEST
        return  response, code

    def __contains__(self, method_name):
        return str(method_name) in self.support_methods

    def __call__(self, *args, **kwargs):
        return self.current_wrapper(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self.call, name)


@OnlineScoreRequest(target_handler='get_score(store, phone, email, birthday=birthday, gender=gender, '
                                   'first_name=first_name, last_name=last_name)',
                    validate_rule='(first_name & last_name) | (email & phone) | (gender & birthday)')
@MethodRequest
def method_handler(request, ctx, store):
    response, code = None, None
    return response, code


arg = {'method': 'online_score',
       'account': '123001234',
       'login': 'freebsd',
       'token': hashlib.sha512(('123001234' + 'freebsd' + SALT).encode()).hexdigest(),
       'arguments': '{"phone": "79175002040", "email": "stupnikov@otus.ru", "gender": 1, "birthday": "26.10.1952", "first_name": "stanislav", "last_name1": "stulenkov"}'
       }

print(method_handler(arg, None, None))
print(method_handler.method)

#
print(method_handler.account)
# print(method_handler.arguments)
# print(method_handler.arguments['phone'])
# print('mail:{}'.format(method_handler.email))

# auth_str = '123001234' + 'freebsd' + SALT
# digest = hashlib.sha512(auth_str.encode()).hexdigest()
# print('token:{}'.format(digest))
# print(method_handler.check_auth)
# print(method_handler.phone.value)
print(method_handler.first_name)
print(method_handler.email)
print(method_handler.birthday)
# print('gender:{}'.format(method_handler.gender))
#
# print(method_handler.last_name.value)


#   print('method:{}'.format(request['method']))
#     print('args: {}'.format(request['args']))
