from zope.interface import Interface

class IHorusUserClass(Interface):
    pass

class IHorusUserAccountClass(Interface):
    pass

class IHorusActivationClass(Interface):
    pass

class IHorusGroupClass(Interface):
    pass

class IHorusLoginSchema(Interface):
    pass

class IHorusLoginForm(Interface):
    pass

class IHorusRegisterSchema(Interface):
    pass

class IHorusRegisterEmailSchema(Interface):
    pass

class IHorusRegisterForm(Interface):
    pass

class IHorusRegisterEmailForm(Interface):
    pass

class IHorusForgotPasswordForm(Interface):
    pass

class IHorusForgotPasswordSchema(Interface):
    pass

class IHorusResetPasswordForm(Interface):
    pass

class IHorusResetPasswordSchema(Interface):
    pass

class IHorusProfileForm(Interface):
    pass

class IHorusProfileSchema(Interface):
    pass

class IHorusVelruseStore(Interface):
    pass
