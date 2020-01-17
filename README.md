# ESAM - Elementary SSH accounts management

## Purpose

Used to create user accounts on many managed nodes, configure SSH access for these accounts and conveniently connect to managed nodes from user workstations

## Features

* Cryptographic protection of the authenticity of data stored in the database is used, which complicates the creation of user accounts on managed nodes by an attacker who obtained unauthorized access to the database. All data of all users and managed nodes is signed by a verification key or user key whose data, in turn, is also signed by a verification key or another user's key, etc. Agents, that directly configure user accounts on managed nodes, verify the authenticity of the received data and configure only those accounts whose data successfully passes authentication checks

* Caching of data about managed nodes at user workstations is used, which allows connecting to managed nodes without network access to the database. Cached data is also pre-tested for authenticity

* A notification about changing data in the database is used, which allows you to quickly (re-) configure user accounts and connect to managed nodes with up-to-date connection parameters

## Components

* Director (`esamd`) - stores data about users and managed nodes, responds to requests from Clients and Agents

* Client (`esamc`) - allows you to change the data of users and managed nodes, receives data about users and managed nodes from the Director, checks the received data and caches them. Provides fast connectivity to managed nodes via SSH

* Agent (`esama`) - receives users data from the Director, checks the received data and sets up user accounts on the managed node

## Access rights

User roles:

* Owner - can change the data of all users (except for another Owner) and managed nodes

* Security Administrator - can change the data of Engineers and managed nodes

* Engineer - cannot change data of users and managed nodes

All users can receive data about users and managed nodes, as well as change their password, which is used to elevate privileges on managed nodes

Agents can only receive users data

The user roles hierarchy is also consider when performing data authenticity checks:

* data of Engineer can only be signed by the Security Administrator, Owner or verification key

* data of Security Administrator can only be signed by the Owner or verification key

* data of Owner can only be signed with a verification key

* data of managed node can only be signed by the Security Administrator, Owner or verification key

## Quick start

* create a database (node with the Director):
  ```bash
  esamd init-db
  ```

* run Director (node with Director):
  ```bash
  esamd start --listen-addr 127.0.0.1 --listen-port 32000 --tls-key tls-key --tls-cert tls-cert
  ```

* generate a pair of private and public keys for verifying the authenticity of data (Owner’s workstation):
  ```bash
  esamc gen-key --esam-key verify-key --esam-pub-key verify-pub-key
  ```

* generate a pair of the Owner’s private and public keys (Owner’s workstation):
  ```bash
  esamc gen-key --esam-key esam-key --esam-pub-key esam-pub-key
  ```

* send an access request (Owner's workstation):
  ```bash
  esamc send-access-req --esam-pub-key esam-pub-key --name owner --dir-addr 127.0.0.1 --dir-port 32000
  ```

* add Owner without signing his data, through a Unix socket used for local management of the Director (node with Director):
  ```bash
  esamc add-user --dir-uds-path esamd.socket
  ```

* connect to the Director as Owner (Owner's workstation):
  ```bash
  esamc login --esam-key esam-key --dir-addr 127.0.0.1 --dir-port 32000  --verify-key verify-pub-key
  ```

* sign Owner data with the verification key (Owner's workstation):
  ```bash
  esamc update-user --name owner --sign-key verify-key
  ```

Now you can add users and managed nodes using only the Owner key, without the need to use the `--sign-key` option and the verification key

* start the Agent, its keys will be automatically generated and an access request sent (managed node):
  ```bash
  esama start --esam-key esama-key --dir-addr 127.0.0.1 --dir-port 32000 --verify-key verify-pub-key
  ```

* add managed node (Owner's workstation):
  ```bash
  esamc add-node
  ```

Now you can connect to the managed node (Owner's workstation):

```bash
esamc ssh node-1
```
