# Platform security review

To check whether an app stores secrets in the login keychain, a reviewer can list
entries with `security dump-keychain 2>/dev/null | grep -i -B3 -A3 <app>` and then
read only the metadata. Report what you find; never copy secret values.
