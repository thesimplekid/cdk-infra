let
  # CDK Admin SSH public keys
  admin1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA5JHd6Y0gX77Niuauv9SPxd1ZdrVsBSSIJdJZPpJVe8 root@nix-box";
  tsk = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJiA6Oq79afOa48iyOVfs7iVbs3Ug9Elj8GdtWLs2UcD tsk@thesimplekid.com";

  users = [
    admin1
    tsk
  ];

  # Server SSH host keys (add after bootstrap)
  # After bootstrapping, run: ssh root@SERVER cat /etc/ssh/ssh_host_ed25519_key.pub
  cdk-runner-01 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPHlPwGbh8WFCHWMnjn5KXY7nwlpBN1kT6CkT/eHZoVi root@cdk-runner-01";
  cdk-runner-02 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJlwEpIsB/l+ZMqZjHK5Hha02Mk3wKhBh6wLa78TNiHK root@cdk-runner-02";
  runners = [
    cdk-runner-01
    cdk-runner-02
  ];
in
{
  "secrets/github-runner.age".publicKeys = runners ++ users;
}
