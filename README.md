# Ansible Collection - schoenserver.general

Documentation for the collection.

## Development

Molecule tests require podman for executing the playbook within a container.

Setup venv for molecule:

```shell
python3 -m venv molecule-venv
source molecule-venv/bin/activate
pip install -r requirements.txt
```

### Run molecule Tests

cd into the role director and create molecule

```shell
cd roles/my_role
../../molecule-venv/bin/molecule test
```
