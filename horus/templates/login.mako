<html>
  <body>
    <a href="${request.route_url('index')}">Back to Index</a>
    % for type in ['success', 'error', 'warning', 'info']:
      % if request.session.peek_flash(type):
        % for message in request.session.pop_flash(type):
          <div class="alert-message ${type}">
            <p><strong>${message}</strong></p>
          </div>
        % endfor
      % endif
    % endfor
    <h1>Login</h1>
    ${form|n}

    % if velruse_forms:
        % for provider_form in velruse_forms:
            ${provider_form|n}
        % endfor
    % endif

    <a href="${request.route_url('forgot_password')}">Forgot Password</a>
  </body>
</html>
