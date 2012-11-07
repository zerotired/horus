from pyramid.i18n       import TranslationStringFactory
from pyramid.i18n       import get_localizer
from pyramid.security   import unauthenticated_userid
from horus.forms        import ProviderForm
from horus.interfaces   import IHorusUserAccountClass
from horus.interfaces   import IHorusVelruseStore
from horus.schemas      import AccountProviderSchema

tsf = TranslationStringFactory('horus')

def translate(string, request):
    localizer = get_localizer(request)
    return localizer.translate(tsf(string))



def get_user_account(request):
    userid = unauthenticated_userid(request)
    user_account_class = request.registry.queryUtility(IHorusUserAccountClass)

    if userid is not None:
        return user_account_class.get_by_id(request, userid)

    return None


def generate_velruse_forms(request, came_from, provider_form=ProviderForm, buttons=None):
    """ Generates variable form based on OpenID providers supported in
    the CONFIG.yaml file
    """
    buttons = buttons and buttons or {}
    velruse_forms = []
    providers = request.registry.settings.get('login_providers', None)
    if not providers:
        providers = request.registry.settings.get('horus.providers', None)
        providers = providers and [x.strip() for x in providers.split(',')] or None
    provider_url_prefix = request.registry.settings.get('horus.provider.url_prefix', '/velruse/login')
    schema = AccountProviderSchema().bind(request=request)


    if providers:
        for provider in providers:
            action = '%s/%s' % (provider_url_prefix, provider)
            button = (buttons.get(provider, provider),)
            form = provider_form(schema, action=action, buttons=button)
            appstruct = dict(
                end_point='%s?csrf_token=%s&came_from=%s' %\
                          (request.route_url('horus_velruse_login_complete'),\
                           request.session.get_csrf_token(),
                           came_from),
                csrf_token = request.session.get_csrf_token(),
                came_from = came_from,
            )
            velruse_forms.append(form.render(appstruct))
    return velruse_forms


def openid_from_token(token, request):
    """ Returns the id from the OpenID Token
    """
    storage = request.registry.queryUtility(IHorusVelruseStore)
    try:
        auth = storage.retrieve(token.encode('UTF-8'))
    except KeyError:
        return None
    if 'profile' in auth:
        auth['id'] = auth['profile']['accounts'][0]['userid']
        auth['provider'] = auth['profile']['accounts'][0]['domain']
        return auth
    return None
