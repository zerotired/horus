from pyramid.security import Authenticated
from pyramid.security import Allow
from pyramid.security import ALL_PERMISSIONS
from horus.interfaces import IHorusUserAccountClass

class BaseFactory(object):
    def __init__(self, request):
        self.request = request
        self.is_root = False

class RootFactory(BaseFactory):
    @property
    def __acl__(self):
        defaultlist = [
            (Allow, 'group:admin', ALL_PERMISSIONS),
            (Allow, Authenticated, 'view'),
        ]

        return defaultlist

    def __init__(self, request):
        super(RootFactory, self).__init__(request)
        self.is_root = True

class UserAccountFactory(RootFactory):
    def __init__(self, request):
        self.request = request
        self.UserAccount = request.registry.getUtility(IHorusUserAccountClass)

    def __getitem__(self, key):
        #user_account = self.request.user_account
        #if int(key) != user_account.id:
        user_account = self.UserAccount.get_by_id(self.request, key)

        if user_account:
            user_account.__parent__ = self
            user_account.__name__ = key

        return user_account
