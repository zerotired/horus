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

class VelruseAccountCreated(BaseEvent):
    def __init__(self, request, user_account, velruse_payload):
        super(VelruseAccountCreated, self).__init__(request, user_account)
        self.velruse_payload = velruse_payload
