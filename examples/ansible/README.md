
```bash
ssh-keygen -t rsa -a 2048
echo "@cert-authority *.example.local $(curl http://host.ca.example.local/crypto/public)" >> .ssh/known_hosts
echo "user.ca.example.local $(curl http://user.ca.example.local/crypto/public)" >> .ssh/known_hosts
ssh ca_user
ssh cs_user 'ticket' > ~/.ssh/id_rsa-cert.pub
ssh host01.example.local
```