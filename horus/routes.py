from horus.resources import UserFactory

def build_routes(config):
    """ Add routes to the config """
    config.add_route('login', '/login')
    config.add_route('logout', '/logout')
    config.add_route('register', '/register')
    config.add_route('activate', '/activate/{user_id}/{code}', factory=UserFactory)
    config.add_route('forgot_password', '/forgot_password')
    config.add_route('reset_password', '/reset_password/{code}')
    config.add_route('profile', '/profile/{user_id}', factory=UserFactory,
            traverse="/{user_id}")
    config.add_route('edit_profile', '/profile/{user_id}/edit', factory=UserFactory,
            traverse="/{user_id}")

