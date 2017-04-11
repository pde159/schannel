# schannel Cookbook

[![Build Status](https://)](https://)

This cookbook manage the windows security channels.

## Requirements

### Platforms

- Windows 2008+

### Chef

- Chef 12.6+

### Recipes

- `default`: The default recipe configure the security channel.
- `unset`: This recipe restore the default windows configuration.

### Usage

This cookbook provides a default recipe to manage security channels on windows servers:
- Protocols (SSL, TLS)
- Ciphers (rc2, rc4, AES, DES)
- Hashes (MD5, SHA)
- Key Exchange Algorithms (PCKS,ECDH, Diffie-Hellman)

Add the schannel::default recipe in your run list to set the security best practises configuration.
Use the schannel::unset to restore the default windows configuration.
Customize your security configuration using attributes.

## Attributes

Attribute                                         | Default Value | Description
------------------------------------------------- | ------------- | ------------------------------------------------------
`default['schannel']['event_logging']['level']`   | 1             | Is the URL of the package repository.
`default['schannel']['cipher_order']['secure']`   | true          | Define the security level 
`default['schannel']['protocols_client_side']`    | true          | Apply the protocol configuration at the client side.

Others available attributes are used to enable/disable a protocol, cipher, hash or exchange key algorithm.
Please check `defaut.rb` attribute file for more details.

You can also define your own list of ciphers via `default['schannel']['cipher_order']['list']` attribute.
Please check `defaut.rb` attribute file for more details.

## Run list

### schannel::default
Just include `schannel` in your node's `run_list`:

```json
{
  "name":"my_node",
  "run_list": [
    "recipe[schannel]"
  ]
}
```

## License and Authors

- Author: Pierre DEPREY (pdeprey@gmail.com)

```text
Copyright:: 2016-2017, pde159

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```