from anykeystore.store import create_store_from_settings
from pyramid.security   import unauthenticated_userid
from horus.forms        import ProviderForm
from horus.interfaces   import IHorusUserAccountClass
from horus.interfaces   import IHorusVelruseStore
from horus.schemas      import AccountProviderSchema


def get_user_account(request):
    userid = unauthenticated_userid(request)
    user_account_class = request.registry.queryUtility(IHorusUserAccountClass)

    if userid is not None:
        return user_account_class.get_by_id(request, userid)

    return None


def generate_velruse_forms(request, came_from):
    """ Generates variable form based on OpenID providers supported in
    the CONFIG.yaml file
    """
    velruse_forms = []
    providers = request.registry.settings.get('horus.velruse.providers', None)
    schema = AccountProviderSchema().bind(request=request)


    if providers:
        providers = [x.strip() for x in providers.split(',')]
        for provider in providers:
            action = '/velruse/login/%s' % provider
            buttons = (provider,)
            form = ProviderForm(schema, action=action, buttons=buttons)
            appstruct = dict(
                end_point='%s?csrf_token=%s&next=%s' %\
                          (request.route_url('horus_velruse_callback'),\
                           request.session.get_csrf_token(),
                           came_from),\
                csrf_token = request.session.get_csrf_token(),
            )
            velruse_forms.append(form.render(appstruct))
    return velruse_forms


def openid_from_token(token, request):
    """ Returns the id from the OpenID Token
    """
    storage = request.registry.queryUtility(IHorusVelruseStore)
    try:
        auth = storage.retrieve(token)
    except KeyError:
        return None
    if 'profile' in auth:
        auth['id'] = auth['profile']['accounts'][0]['userid']
        auth['provider'] = auth['profile']['accounts'][0]['domain']
        return auth
    return None
