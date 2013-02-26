from pyramid.view           import view_config
from pyramid.url            import route_url
from pyramid.security       import remember
from pyramid.security       import forget
from pyramid.security       import NO_PERMISSION_REQUIRED
from pyramid.httpexceptions import HTTPFound, HTTPNotImplemented
from pyramid.httpexceptions import HTTPNotFound
from pyramid.settings       import asbool

from pyramid_mailer         import get_mailer
from pyramid_mailer.message import Message

from horus.interfaces       import IHorusUserClass, IHorusRegisterEmailSchema, IHorusRegisterEmailForm
from horus.interfaces       import IHorusUserAccountClass
from horus.interfaces       import IHorusActivationClass
from horus.interfaces       import IHorusLoginForm
from horus.interfaces       import IHorusLoginSchema
from horus.interfaces       import IHorusRegisterForm
from horus.interfaces       import IHorusRegisterSchema
from horus.interfaces       import IHorusForgotPasswordForm
from horus.interfaces       import IHorusForgotPasswordSchema
from horus.interfaces       import IHorusResetPasswordForm
from horus.interfaces       import IHorusResetPasswordSchema
from horus.interfaces       import IHorusProfileForm
from horus.interfaces       import IHorusProfileSchema
from horus.events           import NewRegistrationEvent
from horus.events           import RegistrationActivatedEvent
from horus.events           import PasswordResetEvent
from horus.events           import ProfileUpdatedEvent
from horus.events           import LoggedInEvent
from horus.events           import VelruseAccountCreatedEvent
from horus.events           import VelruseAccountLoggedInEvent
from hem.db                 import get_session
from horus.lib              import generate_velruse_forms
from horus.lib              import openid_from_token
from horus.lib              import translate

import deform
import pystache


import logging

log = logging.getLogger(__name__)

def authenticated(request, user_account, new_account=False):
    """ This sets the auth cookies and redirects to the page defined
        in horus.login_redirect, defaults to a view named 'index'.
        If a ``came_from`` request parameter is found, this value is used
        for redirection instead.
    """
    settings = request.registry.settings
    headers = remember(request, user_account.id)
    autologin = asbool(settings.get('horus.autologin', False))

    loggedin_event = LoggedInEvent(request, user_account, new_account)
    request.registry.notify(
        loggedin_event
    )

    # resolve `came_from` first try from query params
    login_redirect_view = request.params.get('came_from')
    # next from session (and delete the key if exists)
    if not login_redirect_view:
        login_redirect_view = request.session.get('came_from')
        if login_redirect_view:
            del request.session['came_from']
            # last fallback to configured url
    if not login_redirect_view:
        login_redirect_view = route_url(settings.get('horus.login_redirect', 'index'), request)

    if hasattr(loggedin_event, 'location'):
        location = "%s?came_from=%s" % (loggedin_event.location, login_redirect_view)
        return HTTPFound(location=location, headers=headers)

    if not autologin:
        request.session.flash(translate( u"Logged in successfully.", request), 'success')

    return HTTPFound(location=login_redirect_view, headers=headers)

def create_activation(request, user_account, route_name='horus_activate',
                      template=None, subject=None, body=None):
    template = template and template or translate(u"Please activate your e-mail address by visiting {{ link }}", request)
    subject = subject and subject or translate(u"Please activate your e-mail address!", request)
    db = get_session(request)
    Activation = request.registry.getUtility(IHorusActivationClass)
    activation = Activation()

    db.add(activation)
    user_account.activation = activation

    db.flush()

    if body is None:
        body = pystache.render(template,
            {
                'link': request.route_url(route_name, user_account_id=user_account.id, code=user_account.activation.code)
            }
        )

    subject = subject

    message = Message(subject=subject, recipients=[user_account.email], body=body)

    mailer = get_mailer(request)
    if request.registry.settings.get('mail.queue_path') is not None:
        mailer.send_to_queue(message)
    else:
        mailer.send(message)


class BaseController(object):
    @property
    def request(self):
        # we defined this so that we can override the request in tests easily
        return self._request

    def __init__(self, request):
        self._request  = request
        self.settings = request.registry.settings
        self.User = request.registry.getUtility(IHorusUserClass)
        self.UserAccount = request.registry.getUtility(IHorusUserAccountClass)
        self.Activation = request.registry.getUtility(IHorusActivationClass)
        self.db = get_session(request)

    def translate(self, string):
        return translate(string, self.request)

class AuthController(BaseController):
    def __init__(self, request):
        super(AuthController, self).__init__(request)

        schema = request.registry.getUtility(IHorusLoginSchema)
        self.schema = schema().bind(request=self.request)

        form = request.registry.getUtility(IHorusLoginForm)

        self.login_redirect_view = route_url(self.settings.get('horus.login_redirect', 'index'), request)
        self.login_redirect_view = request.params.get('came_from', self.login_redirect_view)
        self.logout_redirect_view = route_url(self.settings.get('horus.logout_redirect', 'index'), request)
        self.require_activation = asbool(self.settings.get('horus.require_activation', True))
        self.allow_inactive_login = asbool(self.settings.get('horus.allow_inactive_login', False))

        self.form = form(self.schema)
        self.velruse_forms = generate_velruse_forms(request, self.login_redirect_view)


    @view_config(route_name='horus_login', renderer='horus:templates/login.mako', permission=NO_PERMISSION_REQUIRED)
    def login(self):
        if self.request.user_account:
            return HTTPFound(location=self.login_redirect_view)

        # save 'came_from' to session because a query param would not survive a velruse login
        came_from = self.request.params.get('came_from')
        if came_from:
            self.request.session['came_from'] = came_from

        if self.request.method == 'GET':
            return {'form': self.form.render(), 'velruse_forms': self.velruse_forms}
        elif self.request.method == 'POST':
            try:
                controls = self.request.POST.items()
                captured = self.form.validate(controls)
            except deform.ValidationFailure, e:
                return {'form': e.render(), 'errors': e.error.children}

            username = captured['Username']
            password = captured['Password']

            allow_email_auth = self.settings.get('horus.allow_email_auth', False)

            user_account = self.UserAccount.get_account(self.request, username, password)

            if allow_email_auth:
                if not user_account:
                    user_account = self.UserAccount.get_by_email_password(username,
                            password)

            if user_account:
                if not self.allow_inactive_login:
                    if self.require_activation:
                        if not user_account.is_activated:
                            self.request.session.flash(self.translate(u'Your account is not active, please check your e-mail.'), 'error')
                            return {'form': self.form.render()}

                return authenticated(self.request, user_account)

            self.request.session.flash(self.translate(u"Invalid username/email or password."), 'error')

            return {'form': self.form.render(appstruct=captured)}

    @view_config(permission='view', route_name='horus_logout')
    def logout(self):
        """
        Removes the auth cookies and redirects to the view defined in 
        horus.logout_redirect, defaults to a view named 'index'
        """
        self.request.session.invalidate()
        if self.request.user_account:
            self.request.session.flash(self.translate(u"Logged out successfully."), 'success')
        headers = forget(self.request)

        return HTTPFound(location=self.logout_redirect_view, headers=headers)

    @view_config(route_name='horus_velruse_login_complete', permission=NO_PERMISSION_REQUIRED)
    def velruse_login_complete(self):
        """
        no return value, called with route_url('oauth_callback', request)

        This is the URL that Velruse returns an OpenID request to
        """
        redir = self.request.GET.get('came_from', self.login_redirect_view)
        headers = []

        if 'token' in self.request.POST:
            auth = openid_from_token(self.request.POST['token'], self.request)
        elif self.request.context is not None and hasattr(self.request.context, 'profile'):
            auth = {
                'profile': self.request.context.profile,
                'credentials': self.request.context.credentials,
            }
        if auth:
            auth_info = auth['profile']['accounts'][0]
            username = auth_info.get('username',
                                    auth['profile'].get('preferredUsername',
                                                        auth['profile'].get('displayName')))
            user_account = self.UserAccount.get_by_openid(self.request, auth_info['userid'], auth_info['domain'])
            user = None
            new_account = False

            # If the user is already logged in via a different account,
            # associate the new user_account with that user
            logged_in_user_account = self.request.user_account
            logged_in_user_email = None
            if logged_in_user_account and logged_in_user_account != user_account:
                log.debug("User is logged in, associate the new account of provider %s", auth_info['domain'])
                user = logged_in_user_account.user
                if user.display_name is None or user.display_name == u'':
                    user.display_name = auth['profile'].get('displayName', u'')
                logged_in_user_email = logged_in_user_account.email

            if not user_account:
                if not user:
                    user = self.User(display_name=auth['profile'].get('displayName', u''))
                user_account = self.UserAccount(
                    username=username,
                    openid=int(auth_info['userid']),
                    provider=auth_info['domain'],
                    email=logged_in_user_email
                )
                if auth['profile'].has_key('verifiedEmail') and not user_account.email:
                    user_account.email = auth['profile']['verifiedEmail']
                if not user_account.email and auth['profile'].has_key('emails'):
                    if auth['profile']['emails']:
                        user_account.email = auth['profile']['emails'][0]
                if not user.email:
                    user.email = user_account.email
                user.accounts.append(user_account)
                self.db.add(user)
                self.db.flush()
                self.request.registry.notify(
                    VelruseAccountCreatedEvent(self.request, user_account, auth)
                )
                new_account = True
            elif not user_account.is_activated:
                self.request.session.flash(self.translate(u'Your account is not active, please check your e-mail.'), 'error')
            else:
                if user and user != user_account.user:
                    user_account.user = user
                user_account.email = user_account.email and user_account.email or logged_in_user_email
                self.db.add(user_account)
                self.db.flush()

            self.request.registry.notify(
                VelruseAccountLoggedInEvent(self.request, user_account)
            )
            if user_account.user.active is True and user_account.is_activated:
                return authenticated(self.request, user_account, new_account)
            else:
                log.warn("Velruse login failed, user is not active!")
                self.request.session.flash(self.translate(u"Login failed"), 'error')
        else:
            self.request.session.flash(self.translate(u"Login failed using external login provider"), 'error')
        return HTTPFound(location=redir, headers=headers)

class ForgotPasswordController(BaseController):
    def __init__(self, request):
        super(ForgotPasswordController, self).__init__(request)

        self.enabled = asbool(self.settings.get('horus.enable_password_views', True))
        if self.enabled is False:
            return

        self.forgot_password_redirect_view = route_url(self.settings.get('horus.forgot_password_redirect', 'index'), request)
        self.reset_password_redirect_view = route_url(self.settings.get('horus.reset_password_redirect', 'index'), request)

    @view_config(route_name='horus_forgot_password', renderer='horus:templates/forgot_password.mako')
    def forgot_password(self):
        if self.enabled is False:
            return HTTPNotImplemented()
        schema = self.request.registry.getUtility(IHorusForgotPasswordSchema)
        schema = schema().bind(request=self.request)

        form = self.request.registry.getUtility(IHorusForgotPasswordForm)
        form = form(schema)

        if self.request.method == 'GET':
            if self.request.user_account:
                return HTTPFound(location=self.forgot_password_redirect_view)

            return {'form': form.render()}

        elif self.request.method == 'POST':
            try:
                controls = self.request.POST.items()
                captured = form.validate(controls)
            except deform.ValidationFailure, e:
                return {'form': e.render(), 'errors': e.error.children}

            email = captured['Email']

            user_account = self.UserAccount.get_by_email(self.request, email)
            activation = self.Activation()
            self.db.add(activation)

            user_account.activation = activation

            if user_account:
                mailer = get_mailer(self.request)
                body = pystache.render(self.translate(u"Someone has tried to reset your password, if this was you click here: {{ link }}"),
                    {
                        'link': route_url('horus_reset_password', self.request, code=user_account.activation.code)
                    }
                )

                subject = self.translate(u"Do you want to reset your password?")

                message = Message(subject=subject, recipients=[user_account.email], body=body)
                mailer.send(message)

        # we don't want to say "E-mail not registered" or anything like that
        # because it gives spammers context
        self.request.session.flash(self.translate(u"Please check your e-mail to reset your password."), 'success')
        return HTTPFound(location=self.reset_password_redirect_view)

    @view_config(route_name='horus_reset_password', renderer='horus:templates/reset_password.mako')
    def reset_password(self):
        if self.enabled is False:
            return HTTPNotImplemented()
        schema = self.request.registry.getUtility(IHorusResetPasswordSchema)
        schema = schema().bind(request=self.request)

        form = self.request.registry.getUtility(IHorusResetPasswordForm)
        form = form(schema)

        code = self.request.matchdict.get('code', None)

        activation = self.Activation.get_by_code(self.request, code)

        if activation:
            user_account = self.UserAccount.get_by_activation(self.request, activation)

            if user_account:
                if self.request.method == 'GET':
                        return {
                            'form': form.render(
                                appstruct=dict(
                                    Username=user_account.username
                                )
                            )
                        }

                elif self.request.method == 'POST':
                    try:
                        controls = self.request.POST.items()
                        captured = form.validate(controls)
                    except deform.ValidationFailure, e:
                        return {'form': e.render(), 'errors': e.error.children}

                    password = captured['Password']

                    user_account.password = password
                    self.db.add(user_account)
                    self.db.delete(activation)

                    self.request.registry.notify(
                        PasswordResetEvent(self.request, user_account, password)
                    )

                    self.request.session.flash(self.translate(u"Your password has been reset!"), 'success')

                    return HTTPFound(location=self.reset_password_redirect_view)

        return HTTPNotFound()


class RegisterController(BaseController):
    def __init__(self, request):
        super(RegisterController, self).__init__(request)
        schema = request.registry.getUtility(IHorusRegisterEmailSchema)
        self.schema = schema().bind(request=self.request)

        form = request.registry.getUtility(IHorusRegisterEmailForm)
        self.form = form(self.schema)

        self.register_redirect_view = route_url(self.settings.get('horus.register_redirect', 'index'), request)

        self.require_activation = asbool(self.settings.get('horus.require_activation', True))
        self.allow_registration = asbool(self.settings.get('horus.allow_registration', True))
        self.login_after_activation = asbool(self.settings.get('horus.login_after_activation', False))

        if self.require_activation:
            self.mailer = get_mailer(request)

    @view_config(route_name='horus_register', renderer='horus:templates/register.mako')
    def register(self):
        if self.allow_registration is False:
            return HTTPNotImplemented()

        if self.request.method == 'GET':
            if self.request.user_account:
                return HTTPFound(location=self.register_redirect_view)

            return {'form': self.form.render()}
        elif self.request.method == 'POST':

            try:
                controls = self.request.POST.items()
                captured = self.form.validate(controls)
            except deform.ValidationFailure, e:
                return {'form': e.render(), 'errors': e.error.children}

            email = captured['Email']
            if not hasattr(captured,'Username'):
                captured['Username'] = captured['Email']
            username = captured['Username'].lower()
            password = captured['Password']

            user_account = self.UserAccount.get_by_username_or_email(self.request,
                    username, email
            )

            autologin = asbool(self.settings.get('horus.autologin', False))

            if user_account:
                if user_account.username == username:
                    self.request.session.flash(self.translate(u"That username is already used."), 'error')
                elif user_account.email == email:
                    self.request.session.flash(self.translate(u"That e-mail is already used."), 'error')

                return {'form': self.form.render(self.request.POST)}

            activation = None

            try:

                user = self.User(active=False, email=email)
                user_account = self.UserAccount(username=username, email=email, password=password)
                user.accounts.append(user_account)

                self.db.add(user)


                if self.require_activation:
                    # SEND EMAIL ACTIVATION
                    create_activation(self.request, user_account)
                    self.request.session.flash(self.translate(u"Please check your E-mail for an activation link"), 'success')
                else:
                    if not autologin:
                        self.request.session.flash(self.translate(u"You have been registered, you may login now!"), 'success')

            except Exception as exc:
                self.request.session.flash(exc.message, 'error')
                return {'form': self.form.render()}

            self.request.registry.notify(
                NewRegistrationEvent(self.request, user_account, activation,
                    captured)
            )


            if autologin:
                self.db.flush()

                return authenticated(self.request, user_account)

            return HTTPFound(location=self.register_redirect_view)

    @view_config(route_name='horus_activate')
    def activate(self):
        code = self.request.matchdict.get('code', None)
        user_account_id = self.request.matchdict.get('user_account_id', None)

        activation = self.Activation.get_by_code(self.request, code)

        if activation:
            user_account = self.UserAccount.get_by_id(self.request, user_account_id)

            if user_account.activation != activation:
                return HTTPNotFound()

            if user_account:
                user_account.user.active = True
                self.db.delete(activation)
                self.db.add(user_account)
                self.db.flush()

                self.request.registry.notify(
                    RegistrationActivatedEvent(self.request, user_account, activation)
                )

                self.request.session.flash(self.translate(u"Your e-mail address has been verified."), 'success')

                if self.login_after_activation:
                    headers = remember(self.request, user_account.id)
                    self.request.response.headerlist.extend(headers)
                    return authenticated(self.request, user_account)

                return HTTPFound(location=self.activate_redirect_view)

        return HTTPNotFound()


class ProfileController(BaseController):
    def __init__(self, request):
        super(ProfileController, self).__init__(request)

        self.enabled = asbool(self.settings.get('horus.enable_profile_views', True))
        if self.enabled is False:
            return

        schema = self.request.registry.getUtility(IHorusProfileSchema)
        self.schema = schema().bind(request=self.request)

        form = self.request.registry.getUtility(IHorusProfileForm)
        self.form = form(self.schema)



    @view_config(route_name='horus_profile', renderer='horus:templates/profile.mako')
    def profile(self):
        if self.enabled is False:
            return HTTPNotImplemented()

        pk = self.request.matchdict.get('user_account_id', None)

        user = self.UserAccount.get_by_id(self.request, pk)

        if not user:
            return HTTPNotFound()

        return {'user': user}

    @view_config(permission='access_user_account', route_name='horus_edit_profile',
        renderer='horus:templates/edit_profile.mako')
    def edit_profile(self):
        if self.enabled is False:
            return HTTPNotImplemented()
        user = self.request.context

        if not user:
            return HTTPNotFound()

        if self.request.method == 'GET':
            username = user.username
            email = user.email

            return {
                    'form': self.form.render(
                        appstruct= dict(
                            Username=username,
                            Email=email if email else '',
                        )
                    )
                }
        elif self.request.method == 'POST':
            try:
                controls = self.request.POST.items()
                captured = self.form.validate(controls)
            except deform.ValidationFailure, e:
                # We pre-populate username
                e.cstruct['Username'] = user.username
                return {'form': e.render(), 'errors': e.error.children}

            email = captured.get('Email', None)

            if email:
                email_user = self.UserAccount.get_by_email(self.request, email)

                if email_user:
                    if email_user.id != user.id:
                        self.request.session.flash(self.translate(u"That e-mail is already used."), 'error')

                        return HTTPFound(location=self.request.url)

                user.email = email

            password = captured.get('Password')

            if password:
                user.password = password

            self.request.session.flash(self.translate(u"Profile successfully updated."), 'success')

            self.db.add(user)

            self.request.registry.notify(
                ProfileUpdatedEvent(self.request, user, captured)
            )

            return HTTPFound(location=self.request.url)
