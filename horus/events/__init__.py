class BaseEvent(object):
    def __init__(self, request, user_account):
        self.request = request
        self.user_account = user_account

class NewRegistrationEvent(BaseEvent):
    def __init__(self, request, user_account, activation, values):
        super(NewRegistrationEvent, self).__init__(request, user_account)

        self.activation = activation
        self.values = values

class RegistrationActivatedEvent(BaseEvent):
    def __init__(self, request, user_account, activation):
        super(RegistrationActivatedEvent, self).__init__(request, user_account)
        self.activation = activation

class PasswordResetEvent(BaseEvent):
    def __init__(self, request, user_account, password):
        super(PasswordResetEvent, self).__init__(request, user_account)
        self.password = password

class ProfileUpdatedEvent(BaseEvent):
    def __init__(self, request, user_account, values):
        super(ProfileUpdatedEvent, self).__init__(request, user_account)
        self.values = values

class LoggedInEvent(BaseEvent):
    def __init__(self, request, user_account, new_account):
        super(LoggedInEvent, self).__init__(request, user_account)
        self.new_account = new_account

class VelruseAccountCreatedEvent(BaseEvent):
    def __init__(self, request, user_account, velruse_payload):
        super(VelruseAccountCreatedEvent, self).__init__(request, user_account)
        self.velruse_payload = velruse_payload

class VelruseAccountLoggedInEvent(BaseEvent):
    pass
