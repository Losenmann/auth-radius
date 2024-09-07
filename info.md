# Auth RADIUS
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
[![Home Assistant](https://img.shields.io/badge/home%20assistant-%2341BDF5.svg?style=for-the-badge&logo=home-assistant&logoColor=white)](https://www.home-assistant.io)
[![HACS](https://img.shields.io/badge/HACS-Custom-41BDF5.svg?style=for-the-badge)](https://hacs.xyz)
[![Release](https://img.shields.io/github/release/Losenmann/auth-radius/all.svg?style=for-the-badge)](https://github.com/Losenmann/auth-radius/releases)
[![Maintainer](https://img.shields.io/badge/MAINTAINER-%40Losenmann-red?style=for-the-badge)](https://github.com/Losenmann)

Python script for Home Assistant adding authentication via RADIUS\
The project is based on the library [pyrad](https://github.com/pyradius/pyrad.git)

## Overview
The script is designed to authenticate users in Home Assistant via a RADIUS server. This allows you to centrally manage user access.<br>
The script supports 2 launch modes: [auth_providers](#usage-in-auth_provider-mode) and [CLI](#usage-in-cli-mode).
For correct operation, you must add to the [dictionary](./dictionary) in the RADIUS server dictionary file.

## Install
[![](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=losenmann&repository=auth-radius&category=python_script)

- **Method 1.** [HACS](https://hacs.xyz) > Python Script > Add > Auth Radius > Install

- **Method 2.** Copy the manually  `auth-radius.py` from [latest release](https://github.com/Losenmann/auth-radius/releases/latest) to path `/config/python_scripts`

## Usage in auth_provider mode
### Setupe
- **Home Assistant**
   1. Set connection parameters in the `secrets.yaml` file
      ```yaml
      radius_server: "dns_or_ip_addreess_radius_server"
      radius_secret: "radius_server_secret"
      ```
   2. In the `configuration.yaml` file add the configuration, the authentication order matters
      ```yaml
      homeassistant:
        auth_providers:
          - type: command_line
            command: '/usr/local/bin/python'
            args: ['/config/python_scripts/auth-radius.py', '-m']
            meta: true
          - type: homeassistant
      ```
> [!NOTE]
> You can remove the `meta: true` directive so that the script does not write some variables to standard output to populate the user account created in Home Assistant with additional data

- **RADIUS**
   1. Add data from the file [dictionary](./dictionary) to the RADIUS server's `dictionary` file
   2. Set the user's `Hass-Group` attribute to `system-users`

      | Attribute | Type | Value | Description |
      | :-- | :--: | :-----: | :---------- |
      | `Hass-Group` | string | system-users <br> system-admin | User group |
      | `Hass-Local-Only` | byte | 0 <br> 1 | Local login only <br> (Defaults to 0) |
      | `Hass-Is-Active` | byte  | 0 <br> 1 | Activate user account <br> (Defaults to 1) |

## Usage in CLI mode
In CLI mode, you need to set execution permissions `chmod +x ./python_scripts/auth-ldap.py`<br>
Or run via Python `python ./python_scripts/auth-radius.py`
> [!NOTE]
> RADIUS connection parameters can be configured in `secrets.yaml`, see point 1 of the chapter [Usage in auth_provider mode](#usage-in-auth_provider-mode)
```
./python_scripts/auth-radius.py -U 'username' -P 'password' -s 'radius.example.com' -S 'secret'
```

## Script arguments
| key  | type | description |
| :--- | :--: | :---------- |
| `-h` | boolean | Get help information |
| `-m` | boolean | Enable meta to output credentials to stdout <br> (Defaults to False) |
| `-U` | string  | Username |
| `-P` | string  | Password |
| `-s` | string  | RADIUS server <br> (Defaults from `secrets.yaml`) |
| `-S` | string  | RADIUS secret <br> (Defaults from `secrets.yaml`) |
