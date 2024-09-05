# Auth RADIUS
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
[![Home Assistant](https://img.shields.io/badge/home%20assistant-%2341BDF5.svg?style=for-the-badge&logo=home-assistant&logoColor=white)](https://www.home-assistant.io)
[![HACS](https://img.shields.io/badge/HACS-Custom-41BDF5.svg?style=for-the-badge)](https://hacs.xyz)
[![Release](https://img.shields.io/github/release/Losenmann/auth-radius/all.svg?style=for-the-badge)](https://github.com/Losenmann/auth-radius/releases)
[![Maintainer](https://img.shields.io/badge/MAINTAINER-%40Losenmann-red?style=for-the-badge)](https://github.com/Losenmann)

Python script for Home Assistant adding authentication via RADIUS\
The project is based on the library [pyrad](https://github.com/pyradius/pyrad.git)

## Install
[![](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=losenmann&repository=auth-radius&category=python_script)

- **Method 1.** [HACS](https://hacs.xyz) > Python Script > Add > Auth Radius > Install

- **Method 2.** Copy the manually  `auth-radius.py` from [latest release](https://github.com/Losenmann/auth-radius/releases/latest) to path `/config/python_scripts`

## Setupe
- **Home Assistant**
   1. Set connection parameters in the `secrets.yaml` file
      ```yaml
      radius_host: "dns_or_ip_addreess_radius_server"
      radius_secret: "radius_server_secret"
      ```
   2. In the `configuration.yaml` file add the configuration, the authentication order matters
      ```yaml
      homeassistant:
        auth_providers:
          - type: command_line
            command: '/usr/local/bin/python'
            args: ['/config/python_scripts/auth-radius.py', '--meta']
            meta: true
          - type: homeassistant
      ```
   You can remove the `meta:true` directive so that the script does not write some variables to standard output to populate the user account created in Home Assistant with additional data

- **RADIUS**
   1. Add data from the file [dictionary](./dictionary) to the RADIUS server's `dictionary` file
   2. Set the user's `Hass-Group` attribute to `system-users`

      | Attribute | Type | Value | Description |
      | :-- | :--: | :-----: | :---------- |
      | `Hass-Group` | string | system-users <br> system-admin | Группа пользователя |
      | `Hass-Local-Only` | byte | 0 <br> 1 | Вход только локально <br> (Defaults to 0) |
      | `Hass-Is-Active` | byte  | 0 <br> 1 | Активировать учетную запись пользователя <br> (Defaults to 1) |
