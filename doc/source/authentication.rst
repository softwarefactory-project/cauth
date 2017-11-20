.. toctree::

authentication
==============

Authentication endpoint
-----------------------

cauth exposes a unique authentication endpoint for clients, at "/login". The
authentication parameters can be passed to it as a JSON encoded payload or as a form query. The
contents are dependent on the chosen authentication method.

Example:

.. code-block:: bash

  curl -X POST -i -d '{"method": "Password", "back": "http://localhost:8080", "args": {"username": "user1", "password": "password"} }' -H "Content-Type: application/json" http://cauth_server/login

Password-based authentication
-----------------------------

This authentication method will let the user identify herself with a username and
a password. The users may come from the following backends:

* hard-coded users in cauth's configuration file
* LDAP directory
* the local user database in the `manageSF <http://softwarefactory.enovance.com/r/gitweb?p=managesf.git;a=summary>`_ service from Software Factory

These backends can be used altogether at the same time, so be careful with
potential usernames collisions. The backends are checked in the following
order:

#. configuration file
#. manageSF users
#. LDAP directory

Please note that using hard-coded users in the configuration file should be only
used for quick test deployments; passwords hashes are stored in clear view and adding,
modifying or deleting users requires a service restart.

JSON Payload
............

..code-block: JSON

  {"method": "Password",
   "back": "callback/url",
   "args": {"username": "user",
            "password": "password"}
  }

Configuration
.............

In the cauth config.py file, add the following sections to configure the backend(s)
you would like to use:

hardcoded users
,,,,,,,,,,,,,,,

.. code-block:: python

   auth = {
      'users': {
          "example_username": {
              "lastname": "example user",
              "mail": "user@tests.dom",
              "password": "password",
          },
      },
   }

Users are defined by their username, then a full name, e-mail address, and a
hashed password.

You can generate a hashed password with the following code snippet:

.. code-block:: python

  import crypt
  
  password = crypt.crypt('my_password', 'a_salt')

You can define as many users as you want in this way.

manageSF
,,,,,,,,

.. code-block:: python

   auth = {
      'localdb': {
          'managesf_url': 'https://tests.dom',
      },
   }

LDAP
,,,,

.. code-block:: python

   auth = {
      'ldap': {
          'host': 'my.ldap.url',
          'dn': 'uid=%(username)s,ou=test,dc=corp',
          'sn': 'sn_attribute',
          'mail': 'ldap_account_mail_attribute',
      },
   }

* **dn**: how to build the dn from the username, for the binding
* **sn**: the attribute to use for the full name
* **mail**: the attribute to use as the user's e-mail

LDAP (for Active Directory)
,,,,,,,,,,,,,,,,,,,,,,,,,,,

This example illustrates how to use LDAP authentication in a more
arbitrary scenario. In this case, the user account used to bind to the
directory does not map directly to the cn, and a search filter has to
look up the user's information.

.. code-block:: python

   auth = {
      'ldap': {
          'host': 'ldap://adc00.branch.example.com',
          'dn': '%(username)s@branch.example.com',
          'basedn': 'ou=people,dc=branch,dc=example,dc=com',
          'sfilter': '(&(objectClass=user)(sAMAccountName=%(username)s))',
          'sn': 'name',
          'mail': 'mail',
      },
   }

* **host**: the ldap URI to bind to
* **dn**: the user's login, used to bind to the ldap directory
* **basedn**: the base distinguished name, used to start the ldap search from
* **sfilter**: the search filter, used to match the user's entry
* **sn**: the attribute to use for the full name
* **mail**: the attribute to use as the user's e-mail

Login with GitHub
-----------------

This authentication method will let the user identify herself through GitHub.
The following methods are supported:

* oAuth authentication, where the user is redirected to Github to login there
  and authorize access to the user's data
* authentication with a `personal access token <https://github.com/settings/tokens>`_

It is possible to filter users by their declared organizations on GitHub.

JSON Payload
............

oAuth authentication

..code-block: JSON

  {"method": "Github",
   "back": "callback/url",
   "args": {}
  }

Personal access token authentication

..code-block: JSON

  {"method": "GithubPersonalAccessToken",
   "back": "callback/url",
   "args": {"token": "your_github_token"}
  }


Configuration
.............

on GitHub
,,,,,,,,,

You have to register your application in Github to enable Github authentication.

#. Login to your Github account, go to Settings -> Applications -> “Register new application”
#. Fill in the details and be careful when setting the authorization URL. It will look like this: http://yourdomain/auth/login/github/callback

You will need the client ID and client secret generated by GitHub for the configuration of cauth.

on cauth
,,,,,,,,

In the cauth config.py file, add the following section:

.. code-block:: python

   auth = {
    'github': {
        'top_domain': 'tests.dom',
        'auth_url':  'https://github.com/login/oauth/authorize',
        'redirect_uri': 'https://github/redirect/url',
        'client_id': 'your_github_app_id',
        'client_secret': 'your_github_app_secret',
        'allowed_organizations': 'your_allowed_organizations'
    },
   }

OpenID
------

This authentication method lets the user authenticate herself through an OpenID
provider specified in the configuration of cauth.
The user is expected to share her nickname, e-mail address and full name with
cauth (as prompted by the OpenID provider)

JSON Payload
............

..code-block: JSON

  {"method": "OpenID",
   "back": "callback/url",
   "args": {}
  }

Configuration
.............

In the cauth config.py file, add the following section:

.. code-block:: python

   auth = {
    'openid': {
        'auth_url':  'https://your.openid.provider/url',
        'redirect_uri': '/login/openid/callback',
    },
   }

*redirect_uri* will depend on how cauth is served in your configuration; this is
the url (minus the host) where the openid provider must redirect a user after a
successful authentication.
