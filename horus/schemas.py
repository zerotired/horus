import colander
import deform
from pyramid_deform import CSRFSchema
from translationstring import TranslationStringFactory

_ = TranslationStringFactory('horus')

class LoginSchema(CSRFSchema):
    Username = colander.SchemaNode(
        colander.String(),
        title=_(u"Username")
    )
    Password = colander.SchemaNode(
        colander.String(),
        title=_(u"Password"),
        validator=colander.Length(min=2),
        widget=deform.widget.PasswordWidget()
    )

class RegisterSchema(CSRFSchema):
    Username = colander.SchemaNode(
        colander.String(),
        title=_(u"Username")
    )
    Email = colander.SchemaNode(
        colander.String(),
        title=_(u"Email"),
        validator=colander.Email()
    )
    Password = colander.SchemaNode(
        colander.String(),
        title=_(u"Password"),
        validator=colander.Length(min=2),
        widget=deform.widget.CheckedPasswordWidget()
    )

class RegisterEmailSchema(CSRFSchema):
    Email = colander.SchemaNode(
        colander.String(),
        title=_(u"Email"),
        validator=colander.Email()
    )
    Password = colander.SchemaNode(
        colander.String(),
        title=_(u"Password"),
        validator=colander.Length(min=2),
        widget=deform.widget.CheckedPasswordWidget()
    )

class ForgotPasswordSchema(CSRFSchema):
    Email = colander.SchemaNode(
        colander.String(),
        title=_(u"Email"),
        validator=colander.Email()
    )

class ResetPasswordSchema(CSRFSchema):
    Username = colander.SchemaNode(
        colander.String(),
        title=_(u"Username"),
        widget=deform.widget.TextInputWidget(template='readonly/textinput'),
        missing=colander.null,
    )
    Password = colander.SchemaNode(
        colander.String(),
        title=_(u"Password"),
        validator=colander.Length(min=2),
        widget=deform.widget.CheckedPasswordWidget()
    )

class ProfileSchema(CSRFSchema):
    Username = colander.SchemaNode(
        colander.String(),
        title=_(u"Username"),
        widget=deform.widget.TextInputWidget(template='readonly/textinput'),
        missing=colander.null,
    )
    Email = colander.SchemaNode(
        colander.String(),
        title=_(u"Email"),
        validator=colander.Email()
    )
    Password = colander.SchemaNode(
        colander.String(),
        title=_(u"Password"),
        validator=colander.Length(min=2),
        widget=deform.widget.CheckedPasswordWidget(),
        missing=colander.null
    )

class AdminUserSchema(CSRFSchema):
    Username = colander.SchemaNode(
        colander.String(),
        title=_(u"Username"),
    )
    Email = colander.SchemaNode(
        colander.String(),
        title=_(u"Email"),
        validator=colander.Email()
    )
    Password = colander.SchemaNode(
        colander.String(),
        title=_(u"Password"),
        validator=colander.Length(min=2),
        widget=deform.widget.CheckedPasswordWidget(),
        missing=colander.null
    )

class AccountProviderSchema(colander.Schema):
    end_point = colander.SchemaNode(
        colander.String(),
        widget = deform.widget.HiddenWidget(),
    )
    csrf_token = colander.SchemaNode(
        colander.String(),
        widget = deform.widget.HiddenWidget(),
    )
    came_from = colander.SchemaNode(
        colander.String(),
        widget = deform.widget.HiddenWidget(),
    )
