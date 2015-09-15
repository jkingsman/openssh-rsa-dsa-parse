[![NPM](https://nodei.co/npm/openssh-rsa-dsa-parse.png)](https://nodei.co/npm/openssh-rsa-dsa-parse/)

# openssh-rsa-dsa-parse

Simple, fast parsing of OpenSSH RSA and DSA keys to programmatically access key type, length, and and multiple key formats.

## Getting Started

```
npm install openssh-rsa-dsa-parse
```

Load the module...

```javascript
var opensshparser = require('openssh-rsa-dsa-parse');
```

Then load a key...

```javascript
var newKey = new opensshparser('ssh-rsa AAAAB3NzaC1yc2EAAAABJ[...]');
```

## API

### open-ssh-parser(`yourkey`)

Load and parse an RSA or DSA/DSS OpenSSH key.

* `yourkey` - (String) RSA or DSA key in the format of `ssh-rsa AAAAB3NzaC1yc2EAAAABJ[...]` or `ssh-dss AAAAB3NzaC1kc3MAAACBAJ[...]`

### open-ssh-parser.getKey()

Returns the entire key as a string

### open-ssh-parser.getKeyType()

Return the key type as a string (`ssh-rsa`, `ssh-dss`, etc.)

### open-ssh-parser.getData()

Return the key data as a string

### open-ssh-parser.getKeyLength()

Return the key length (modulus) as a number

### open-ssh-parser.getComment()

Return the key's comment, if it has one, or null

### open-ssh-parser.getByteArray()

Return the entire key as an array of bytes

### open-ssh-parser.getSlicedByteArray()

Interprets the key as a repeating pattern of

`<4 byte data length specifier><data of specified length>`

and returns an array of arrays, with each subarray containing a data chunk as delimited by the above pattern (the length data is discarded).

## Testing

```
npm test
```

## License
MIT.

***

[![Flattr this](http://api.flattr.com/button/flattr-badge-large.png)](https://flattr.com/submit/auto?user_id=jkingsman&url=https%3A%2F%2Fgithub.com%2Fjkingsman%2Fopenssh-rsa-dsa-parse)
