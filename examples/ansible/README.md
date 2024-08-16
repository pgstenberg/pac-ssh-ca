# Example - Ansible

This example describes how you can utilize Ansible as your configuration-management to provision certificates to a set of hosts using the `Simple SSH CA`.

The Ansible master will act as a trusted delegate for host certificates, which gives it the possibility to issue host specific tickets, used for issue and renew it's own certificates that can be trusted by the users.

The Ansible master will also make sure to provision the user certificate CA as a trusted certificate authority for the hosts ssh agents in order to approve connections from users authorized throught the user CA.

This setup uses both the `ansible-pull` and regular `ansible push` features to achieve this. `ansible-pull` is used for periodically issuing new certificates based the provided ticket where `ansible push` is used to actual provision the ticket from the ansible master or delegate.

## Starting the environment

1. Generate new delegate key-pairs
```bash
ssh-keygen -t rsa -a 2048 -N '' -f ./delegate_id_rsa
```
2. Provision the stack
```bash
docker-compose up -d
```

## Testing certificate issued for a user

1. Start user "sandbox environment" container
```bash
docker-compose run client
```
2. Add CA (host certificates) public key as trusted authority in `known_hosts`
```bash
echo "@cert-authority *.example.local $(curl -s http://host.ca.example.local/crypto/public)" >> .ssh/known_hosts
```
3. Add CA (user certificates) public key as trusted key in `known_hosts`
```bash
echo "user.ca.example.local $(curl -s http://user.ca.example.local/crypto/public)" >> .ssh/known_hosts
```
4. Fetch your users login URL
```bash
ssh user.ca.example.local
```
5. Follow the login URL and use the following credentials
`username: user01@example.local`
`password: Password1`
6. Click `Copy to clipboard` and paste the command with the _ticket_ in your terminal
7. Now you should be able to ssh into the hosts without any prompts or warnings
```bash
ssh host01.example.local
ssh host02.example.local
ssh host03.example.local
```

## Testing revoking host certificates


1. Remove the trusted delegate from host CA
```bash
docker-compose exec ca-host bash -c "yq e -i '.delegation.delegates=[]' ./config.yml"
```
2. Restart the CA host
```bash
docker-compose restart ca-host
```
3. The hosts will no longer be able to renew thier certiticate. To confirm - wait 15 min for the certificate to expire and use the user "sandbox" described from above.
```bash
ssh host01.example.local
```
Will prompt you that the public certificate presented by the host is not trusted.

**To add the the delegate trust again**
```bash
docker-compose exec ca-host bash -c "K='$(cat ./delegate_id_rsa.pub)' yq e -i '.delegation.delegates=[strenv(K)]' ./config.yml"
docker-compose restart ca-host
```