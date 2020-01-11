# ESAM - Elementary SSH accounts management

## Purpose

Used to create user accounts on managed nodes, configure SSH access for these accounts and conveniently find and connect to managed nodes from the user's workstation

## Features

* all data of all users is signed by a verification key or by a key of another user whose data, in turn, is also signed by a verification key, etc. Agents, that directly configure accounts on managed nodes, verify the authenticity of the received data and configure only those accounts whose data is verified. This complicates the creation of accounts on managed nodes by an attacker who obtained unauthorized access to the database

* Clients used by users to manage the system and connect to managed nodes via SSH also verify the authenticity of the received data, including data about managed nodes. In addition, Clients cache verified data about managed nodes and provide a quick search for managed nodes with auto-completion

## Components

* Director (`esamd`) - stores data of users and managed nodes, responds to requests from Clients and Agents

* Client (`esamc`) - allows you to change the data of users and managed nodes, receives from the Director lists of users and managed nodes, checks the received data and caches them

* Agent (`esama`) - receives user lists from the Director, checks the received data and sets up accounts on the site

## Access rights

User roles:

* Owner - can change the data of all users (except for another Owner) and managed nodes

* Security Administrator - can change the data of Engineers and managed nodes

* Engineer - cannot change data of users and managed nodes

All users can receive lists of users and managed nodes, as well as change their password used to elevate privileges on managed nodes

Agents can only receive user lists

The user role hierarchy is also consider when performing data authenticity checks:

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

* add Owner without data signature (node with Director):

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

Now you can add / change other users using only the Owner key, without the need to use the `--sign-key` option and the verification key

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
