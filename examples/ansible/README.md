


`docker-compose run user`
```bash
echo "@cert-authority *.example.local $(curl http://host.ca.example.local/crypto/public)" >> .ssh/known_hosts
echo "user.ca.example.local $(curl http://user.ca.example.local/crypto/public)" >> .ssh/known_hosts
ssh user.ca.example.local
ssh user.ca.example.local 'ticket' > ~/.ssh/id_rsa-cert.pub

ssh host01.example.local
ssh host02.example.local
ssh host03.example.local
```