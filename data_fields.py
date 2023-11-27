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