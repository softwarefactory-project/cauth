.. toctree::

Supported components
====================

Hooks are defined in cauth for the following components, so that when a successful
authentication occurs in cauth for the first time, the user will be added to the
component's user backend.

Gerrit
------

Gerrit is a free and open source, web-based team code collaboration and reviewing
tool.

Configuration
.............

Add the HTTP auth to the gerrit config file:

.. code-block:: guess

  [auth]
      type = HTTP

on cauth
,,,,,,,,

Add the following section to cauth's config.py:

.. code-block:: python

  gerrit = {
      'url': 'http://gerrit.url',
      'admin_user': 'admin',
      'admin_password': 'password',
  }

* **url** is the gerrit URL
* **admin_user** is the gerrit admin account
* **admin_password** is the gerrit admin password
* **db_host** is the network address of the gerrit mysql backend
* **db_name** is the name of the database used by gerrit
* **db_user** and **db_password** are the credentials used by gerrit with the database
