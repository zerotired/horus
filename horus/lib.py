from pyramid.security   import unauthenticated_userid
from horus.forms import ProviderForm
from horus.interfaces   import IHorusSession, IHorusUserAccountClass

import hashlib
import random
import string
from horus.schemas import AccountProviderSchema

def generate_random_string(length):
    """Generate a generic hash key for the user to use"""
    m = hashlib.sha256()
    word = ''

    for i in xrange(length):
        word += random.choice(string.ascii_letters)

    m.update(word)

    return unicode(m.hexdigest()[:length])

def get_session(request):
    session = request.registry.getUtility(IHorusSession)

    return session

def get_user_account(request):
    userid = unauthenticated_userid(request)
    user_account_class = request.registry.queryUtility(IHorusUserAccountClass)

    if userid is not None:
        return user_account_class.get_by_id(request, userid)

    return None

def get_class_from_config(settings, key):
    if key in settings:
        user_modules = settings.get(key).split('.')
        module = '.'.join(user_modules[:-1])
        klass = user_modules[-1]
        imported_module = __import__(module, fromlist=[klass])
        imported_class = getattr(imported_module, klass)

        return imported_class
    else:
        raise Exception('Please provide a horus.userclass config option')


def pluralize(singular):
    """Return plural form of given lowercase singular word (English only). Based on
    ActiveState recipe http://code.activestate.com/recipes/413172/

    >>> pluralize('')
    ''
    >>> pluralize('goose')
    'geese'
    >>> pluralize('dolly')
    'dollies'
    >>> pluralize('genius')
    'genii'
    >>> pluralize('jones')
    'joneses'
    >>> pluralize('pass')
    'passes'
    >>> pluralize('zero')
    'zeros'
    >>> pluralize('casino')
    'casinos'
    >>> pluralize('hero')
    'heroes'
    >>> pluralize('church')
    'churches'
    >>> pluralize('x')
    'xs'
    >>> pluralize('car')
    'cars'

    """
    ABERRANT_PLURAL_MAP = {
        'appendix': 'appendices',
        'barracks': 'barracks',
        'cactus': 'cacti',
        'child': 'children',
        'criterion': 'criteria',
        'deer': 'deer',
        'echo': 'echoes',
        'elf': 'elves',
        'embargo': 'embargoes',
        'focus': 'foci',
        'fungus': 'fungi',
        'goose': 'geese',
        'hero': 'heroes',
        'hoof': 'hooves',
        'index': 'indices',
        'knife': 'knives',
        'leaf': 'leaves',
        'life': 'lives',
        'man': 'men',
        'mouse': 'mice',
        'nucleus': 'nuclei',
        'person': 'people',
        'phenomenon': 'phenomena',
        'potato': 'potatoes',
        'self': 'selves',
        'syllabus': 'syllabi',
        'tomato': 'tomatoes',
        'torpedo': 'torpedoes',
        'veto': 'vetoes',
        'woman': 'women',
        }

    VOWELS = set('aeiou')

    if not singular:
        return ''
    plural = ABERRANT_PLURAL_MAP.get(singular)
    if plural:
        return plural
    root = singular
    try:
        if singular[-1] == 'y' and singular[-2] not in VOWELS:
            root = singular[:-1]
            suffix = 'ies'
        elif singular[-1] == 's':
            if singular[-2] in VOWELS:
                if singular[-3:] == 'ius':
                    root = singular[:-2]
                    suffix = 'i'
                else:
                    root = singular[:-1]
                    suffix = 'ses'
            else:
                suffix = 'es'
        elif singular[-2:] in ('ch', 'sh'):
            suffix = 'es'
        else:
            suffix = 's'
    except IndexError:
        suffix = 's'
    plural = root + suffix
    return plural

def generate_velruse_forms(request, came_from):
    """ Generates variable form based on OpenID providers supported in
    the CONFIG.yaml file
    """
    velruse_forms = []
    providers = request.registry.settings.get('horus.velruse_providers', None)
    schema = AccountProviderSchema().bind(request=request)


    if providers:
        providers = [x.strip() for x in providers.split(',')]
        for provider in providers:
            action = '/velruse/login/%s' % provider
            buttons = (provider,)
            form = ProviderForm(schema, action=action, buttons=buttons)
            appstruct = dict(
                end_point='%s?csrf_token=%s&next=%s' %\
                          (request.route_url('velruse_callback'),\
                           request.session.get_csrf_token(),
                           came_from),\
                csrf_token = request.session.get_csrf_token(),
            )
            velruse_forms.append(form.render(appstruct))
    return velruse_forms


def openid_from_token(token, request):
    """ Returns the id from the OpenID Token
    """
    #dbsession = DBSession()
    #auth = json.loads(dbsession.query(KeyStorage.value). \
    #                  filter(KeyStorage.key==token).one()[0])
    storage = request.registry.velruse_store
    auth = storage.retrieve(token)
    if 'profile' in auth:
        auth['id'] = auth['profile']['accounts'][0]['userid']
        auth['provider'] = auth['profile']['accounts'][0]['domain']
        return auth
    return None
