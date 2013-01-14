from anykeystore.store import create_store_from_settings
from horus.schemas      import LoginSchema, RegisterEmailSchema
from horus.schemas      import RegisterSchema
from horus.schemas      import ForgotPasswordSchema
from horus.schemas      import ResetPasswordSchema
from horus.schemas      import ProfileSchema
from horus.forms        import SubmitForm
from horus.resources    import RootFactory
from horus.interfaces   import IHorusUserClass, IHorusRegisterEmailSchema, IHorusRegisterEmailForm
from horus.interfaces   import IHorusUserAccountClass
from horus.interfaces   import IHorusGroupClass
from horus.interfaces   import IHorusActivationClass
from horus.interfaces   import IHorusLoginForm
from horus.interfaces   import IHorusLoginSchema
from horus.interfaces   import IHorusRegisterForm
from horus.interfaces   import IHorusRegisterSchema
from horus.interfaces   import IHorusForgotPasswordForm
from horus.interfaces   import IHorusForgotPasswordSchema
from horus.interfaces   import IHorusResetPasswordForm
from horus.interfaces   import IHorusResetPasswordSchema
from horus.interfaces   import IHorusProfileForm
from horus.interfaces   import IHorusProfileSchema
from horus.interfaces   import IHorusVelruseStore
from horus.lib          import get_user_account
from hem.config         import get_class_from_config

def groupfinder(userid, request):
    user_account = request.user_account
    groups = []

    if user_account:
        if not user_account.is_activated or user_account.user.active is False:
            return groups
        else:
            groups.append('active')

        for group in user_account.user.groups:
            groups.append('group:%s' % group.name)

        groups.append('useraccount:%s' % user_account.id)
        groups.append('user:%s' % user_account.user.id)

    return groups

def includeme(config):
    settings = config.registry.settings
    config.set_request_property(get_user_account, 'user_account', reify=True)

    config.set_root_factory(RootFactory)


    if not config.registry.queryUtility(IHorusUserClass):
        user_class = get_class_from_config(settings, 'horus.user_class')
        config.registry.registerUtility(user_class, IHorusUserClass)

    if not config.registry.queryUtility(IHorusUserAccountClass):
        user_account_class = get_class_from_config(settings, 'horus.user_account_class')
        config.registry.registerUtility(user_account_class, IHorusUserAccountClass)

    if not config.registry.queryUtility(IHorusGroupClass):
        group_class = get_class_from_config(settings, 'horus.group_class')
        config.registry.registerUtility(group_class, IHorusGroupClass)

    if not config.registry.queryUtility(IHorusActivationClass):
        activation_class = get_class_from_config(settings,
                'horus.activation_class')
        config.registry.registerUtility(activation_class,
                IHorusActivationClass)

    if not config.registry.queryUtility(IHorusVelruseStore):
        # setup velruse token storage
        storage_string = settings.get('horus.velruse.store', 'memory')
        settings['horus.velruse.store.store'] = storage_string
        velruse_store = create_store_from_settings(settings, prefix='horus.velruse.store.')
        config.registry.registerUtility(velruse_store,
            IHorusVelruseStore)

    schemas = [
        (IHorusLoginSchema, LoginSchema),
        (IHorusRegisterSchema, RegisterSchema),
        (IHorusRegisterEmailSchema, RegisterEmailSchema),
        (IHorusForgotPasswordSchema, ForgotPasswordSchema),
        (IHorusResetPasswordSchema, ResetPasswordSchema),
        (IHorusProfileSchema, ProfileSchema)
    ]

    forms = [
        IHorusLoginForm, IHorusRegisterForm, IHorusRegisterEmailForm, IHorusForgotPasswordForm,
        IHorusResetPasswordForm, IHorusProfileForm
    ]

    for iface, schema in schemas:
        if not config.registry.queryUtility(iface):
            config.registry.registerUtility(schema, iface)

    for form in forms:
        if not config.registry.queryUtility(form):
            config.registry.registerUtility(SubmitForm, form)

    config.include('horus.routes')
    config.scan()

    config.add_translation_dirs('horus:locale/')
