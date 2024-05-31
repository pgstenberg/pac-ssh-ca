
ssh-keygen -t rsa -a 2048 -N '' -f ./delegate_id_rsa

docker-compose exec ca-host bash -c "K='$(cat ./delegate_id_rsa.pub)' yq e -i '.delegation.delegates=[strenv(K)]' ./config.yml"
docker-compose exec ca-host bash -c "yq e -i '.delegation.delegates=[]' ./config.yml"
docker-compose restart ca-host

`docker-compose run user`
```bash
echo "@cert-authority *.example.local $(curl -s http://host.ca.example.local/crypto/public)" >> .ssh/known_hosts
echo "user.ca.example.local $(curl -s http://user.ca.example.local/crypto/public)" >> .ssh/known_hosts
ssh user.ca.example.local
ssh user.ca.example.local 'ticket' > ~/.ssh/id_rsa-cert.pub

ssh host01.example.local
ssh host02.example.local
ssh host03.example.local
```