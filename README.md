# Foxpass auth plugin for OpenVPN open-source

To install

1) `pip install -r requirements.txt` (might need `sudo`)

2) change your openvpn config to:

```
script-security 2 # 2 allows via-file, 3 allows via-env too
auth-user-pass-verify /path/to/foxpass-auth-user-pass.py via-file
username-as-common-name # without this openvpn will use cn in the certificate as username, instead of what was passed in
duplicate-cn # you may need this if everyone is using same certificate
```

3) copy `foxpass.conf.sample` to `foxpass.conf` (make sure it's in the same directory as the script), and fill in the `api_key` and (optionally) the Duo information
