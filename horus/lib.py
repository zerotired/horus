from pyramid.security   import unauthenticated_userid
from horus.interfaces   import IHorusUserClass

def get_user(request):
    userid = unauthenticated_userid(request)
    user_class = request.registry.queryUtility(IHorusUserClass)

    if userid is not None:
        return user_class.get_by_id(request, userid)

    return None
