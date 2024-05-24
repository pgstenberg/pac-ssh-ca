
```bash
echo "@cert-authority *.ansible_test_local. $(curl http://ca_host/crypto/public)" >> .ssh/known_hosts
echo "@cert-authority ca_user $(curl http://ca_user/crypto/public)" >> .ssh/known_hosts
ssh-keygen -t rsa -i 2048
ssh ca_user
ssh cs_user 'ticket' > ~/.ssh/id_rsa-cert.pub
ssh ansible_host01.ansible_test_local.
```