## DID-Auth-Protocol

This repository defines the specification of ArcBlock DID Auth Protocol.

## Table of Contents
- [DID-Auth-Protocol](#did-auth-protocol)
- [Table of Contents](#table-of-contents)
- [Abstract](#abstract)
- [Motivation](#motivation)
- [Workflow](#workflow)
  - [Pre-knowledge:](#pre-knowledge)
  - [Request DID Authentication](#request-did-authentication)
  - [Response DID Authentication](#response-did-authentication)
  - [Revoke DID Authentication](#revoke-did-authentication)
- [DID](#did)
  - [DID Type](#did-type)
  - [How to create DID](#how-to-create-did)
- [Verifiable Claims](#verifiable-claims)
  - [Profile](#profile)
    - [Predefined claim items:](#predefined-claim-items)
  - [Agreement](#agreement)
  - [Proof of Holding](#proof-of-holding)
- [Use Cases](#use-cases)
- [Registry Blockchain (TBD)](#registry-blockchain-tbd)
    - [Trust level](#trust-level)
- [APIs](#apis)
    - [Wallet APIs](#wallet-apis)
    - [Registry blockchain side APIs](#registry-blockchain-side-apis)
    - [ForgeSDK](#forgesdk)
- [References:](#references)

## Abstract

ArcBlock DID (decentralized identification) Authentication Protocol is an open protocol that provides a secure decentralized authentication mechanism by using asymmetric cryptography technology. This protocol involves tree parties, wallet (the client side agent of the end user), application (the service provider) and ABT chain (the decentralized trust authority). In this protocol we define authentication as the process that the prover proves to the verifier that he or she is in possesses of the secret key of a certain public key. The public key then serves as a bridge which binds the prover with verifier's business logic.

## Motivation

## Workflow

The entire authentication protocol contains three process: Pre-knowledge, Request DID Authentication and Response DID Authentication. We will illustrate each one of them in detail in this section.

### Pre-knowledge:

Pre-knowledge refers that process that wallet gets the information of an application before the real authentication starts. Wallet needs to know the application's DID, application's public key and its service endpoint in advance. This information could be contained in a QR code or a deep link provided by the application.

The following is an example of the QR code content or a deep link.

```
https://arcwallet.io/i?appPk=zBdZEnbDJTijVVCx4Nx68bzDPPMFwVizSRorvzSS3SGG2&appDid=did:abt:zNK7PeUtemp5oAhJ4zNmGJ8rUoFnB1CtKfoU&action=requestAuth&url=https://example-application.io/auth/
```

- `linkPath`: The `linkPath` is located at the beginning of the link, `https://arcwallet.io/i` in this example, and is used to locate the wallet. This part is configurable and the SDK allows developer to register their own domain for application.
  - If the QR code is scanned by a third part camera, e.g. iPhone, wallet should be open and the parameters will be passed to wallet if it is installed. If wallet is not installed, an installation page should be open. The same behavior applies to the case when the user clicks such link. The process illustrated above depends on the deep link technology on different platforms such as [iOS](https://developer.apple.com/ios/universal-links/) and [Android](https://developer.android.com/training/app-links/).
  - If the QR code is scanned by the wallet, this section will be ignored and the parameters will be parsed.
- `appPk`: This parameter is Bitcoin Base58 encoded public key of application. It will be passed to ArcWallet.
- `appDid`: This is the application's DID.
- `action`: Tells the action that wallet should perform in next step. Here the action should be `requestAuth` and the wallet will use `GET` method to access the `url`
- `url`: This parameter is the [x-www-form-urlencoded](https://en.wikipedia.org/wiki/Percent-encoding#The_application.2Fx-www-form-urlencoded_type) URL that will be used by wallet to start the Request DID Authentication process latter.

### Request DID Authentication

After the wallet gathers the information described in previous section it starts the Request DID Authentication process. The main purpose of this process is to acquire the verifiable claims requested by application.

1. First, wallet must calculate a `userDid` for this application. This is intend to protect the user's privacy. We use BIP44 to calculate this `userDid`:
    1. Apply sha3 to the appDid
    2. Take the first 64 bits of the hash
    3. Split the these 64 bits into two 32-bits-long sections denoted as `S1` and `S2`.
    4. Derive the HD secret key by using path `m/44'/ABT'/S1'/S2'/address_index` where ABT' is the coin type registered on SLIP44 and address_index is numbered from index 0 in sequentially increasing manner.
    5. Convert the HD secret key to `userDid` by using the rules described in [DID section](#did).
    6. From this point, the wallet should use this derived secret key, public key and DID for future processing.
2. Encrypt the `userDid` with `appPk`. (TBD)
3. Wallet sends the encrypted `userDid` to the application's requestAuth endpoint.
    ```
    GET https://example-application.io/auth?userDid=encrypted_userDid
    ```
4. The response returned by application should contain two fields `appPk` and `authInfo`.
   - `appPk` is the application's public key, encoded by Bitcoin Base58.
   - `authInfo` is a signed object in JWT format.

   The following is an example response payload.
    ```json
    {
      "appPk": "zBdZEnbDJTijVVCx4Nx68bzDPPMFwVizSRorvzSS3SGG2",
      "authInfo": "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.eyJleHAiOjE1NDg4MDM0MjIsImlhdCI6MTU0ODcwMzQyMiwiaXNzIjoiZGlkOmFidDp6Tkt0Q05xWVdMWVdZVzNnV1JBMXZuUnlrZkNCWllIWnZ6S3IiLCJuYmYiOjE1NDg3MDM0MjIsInJlcXVlc3RlZENsYWltcyI6eyJkb2N1bWVudHMiOlt7Imhhc2giOiJUaGUgaGFzaCBvZiB0aGUgZG9jdW1lbnQncyBjb250ZW50IiwidXJpIjoiaHR0cHM6Ly9kb2N1bWVudC0xLmlvIn0seyJoYXNoIjoiVGhlIGhhc2ggb2YgdGhlIGRvY3VtZW50J3MgY29udGVudCIsInVyaSI6ImlwZnM6Ly9kb2N1bWVudC0yIn1dLCJwcm9maWxlIjpbImZ1bGxOYW1lIiwicGhvbmUiLCJzaGlwcGluZ0FkZHJlc3MiXSwicHJvb2ZPZkhvbGRpbmciOlt7InRva2VuIjoidG9rZW4gbmFtZSAxIiwidmFsdWUiOjE4MDAwMDB9LHsidG9rZW4iOiJ0b2tlbiBuYW1lIDIiLCJ2YWx1ZSI6MTAwMDAwMH1dfSwicmVzcG9uc2VBdXRoVXJpIjoiaHR0cHM6Ly9leGFtcGxlLWFwcGxpY2F0aW9uL3Jlc3BvbnNlLWF1dGgifQ.RasZv6ydSxOBj3H726P8THeo4K4IAd7wapqrdE4hrOVRONByAHYK1kr7uAXASc_-Mw9ShD3IcqAuwnLiEkvHCQ"
    }
    ```

    The header and body part of `authInfo` displayed above decodes as
    ```json
    {
      "alg": "Ed25519",
      "typ": "JWT"
    }
    {
      "iss": "did:abt:zNKtCNqYWLYWYW3gWRA1vnRykfCBZYHZvzKr",
      "iat": 1548703422,
      "nbf": 1548703422,
      "exp": 1548803422,
      "appInfo": {
        "name": "The name of the application",
        "description": "The description of the application.",
        "logo": "https://example-application/logo"
      },
      "action": "responseAuth",
      "url": "https://example-application/auth",
      "requestedClaims": [
        {
          "type": "profile",
          "meta": {
            "description": "Please fill in basic information."
          },
          "items": ["fullName", "mobilePhone", "mailingAddress"]
        },
        {
          "type": "agreement",
          "meta": {
            "description": "The user data usage agreement."
          },
          "uri": "https://document-1.io",
          "hash": {
            "method": "sha256",
            "digest": "The hash result of the document's content"
          }
        },
        {
          "type": "agreement",
          "meta": {
            "description": "The service agreement"
          },
          "uri": "ipfs://document-2",
          "hash": {
            "method": "sha3",
            "digest": "The hash result of the document's content"
          }
        }
      ]
    }
    ```

  - `iss`: The application's DID generated from `appPk`
  - `iat`, `nbf` and `exp`: Follow the JWT standard.
  - `appInfo`:
  - `url`: A must-have field that will be used by wallet in Response DID Authentication process.
  - `action`: Tells what action should the wallet perform in next step. Here it should be `responseAuth` and wallet will use `POST` method to access the `url`.
  - `requestedClaims` is an optional filed. If the user is unknown to the application, it can ask users to identify themselves by returning this filed. We will illustrate the details of this filed in section [Verifiable Claims](#verifiable-claims). The application can also skip this omit this filed if it wants.
5. After gets the response, wallet should do following verifications:
  1. Verifies if the `iat` is later than the request is sent.
  2. Verifies if the response has expired by using `exp`.
  3. Verifies if the signature matches the `appPk` and if the `appPk` matches the appDid in the `iss` field.
6. **(TBD)** The wallet could (may under users' request) ask a registry blockchain for the metadata of the application, `trustLevel` for example. ArcBlock provides ABT chain as a registry chain.
7. **(TBD)** The `trustLevel` can be used by wallet when displaying requested claims to user. For the application whose `appDid` cannot be found on registry blockchain, wallet should make the entire page with high risk mark. If an application is asking verifiable claims whose required trust_level is higher than the `appDid`s', wallet should display those claims with high risk mark.

### Response DID Authentication

This is the last process of the overall workflow. Depends on whether application requires verifiable claims, wallet will either prompt user to fill in requested claims and then go to the responseAuth endpoint or go to the endpoint directly in this process.

1. Wallet should display all requested claims to users and wait for user's input.
2. After user fills all data, wallet signs the payload with the corresponding secret key of the `usr_did` and then send it back to the `url` obtained in Request DID Authentication process in following format.
    ```json
    {
      "userPk": "",
      "userInfo": ""
    }
    ```

    The above `userInfo` decodes as
    ```json
    {
      "alg": "Ed25519",
      "typ": "JWT"
    }
    {
      "iss": "userDid",
      "iat": "1548713422",
      "nbf": "1548713422",
      "exp": "1548813422",
      "requestedClaims": [
        {
          "type": "profile",
          "fullName": "Alice Bean",
          "mobilePhone": "123456789",
          "mailingAddress": {
            "addressLine1": "456 123th AVE",
            "addressLine2": "Apt 106",
            "city": "Redmond",
            "state": "WA",
            "postalCode": "98052",
            "country": "USA"
          }
        },
        {
          "type": "agreement",
          "uri": "https://document-1.io",
          "hash": {
            "method": "sha256",
            "digest": "The hash result of the document's content"
          },
          "agreed": true,
          "sig": "user's signature against the doc hash plus AGREED."
        },
        {
          "type": "agreement",
          "uri": "ipfs://document-2",
          "hash": {
            "method": "sha3",
            "digest": "The hash result of the document's content"
          },
          "agreed": false
        }
      ]
    }
    ```
3. If the application accepts the authentication request, it responses
    ```
    {
      "appPk": "E4852B7091317E3622068E62A5127D1FB0D4AE2FC50213295E10652D2F0ABFC7",
      "jwt": "eyJhbGciOiJFZDI1NTE5IiwidHlwIjoiSldUIn0.eyJleHAiOiIxNTQ4ODk4ODM5IiwiaWF0IjoiMTU0ODg5NzAzOSIsImlzcyI6ImRpZDphYnQ6ek5LdENOcVlXTFlXWVczZ1dSQTF2blJ5a2ZDQlpZSFp2ektyIiwibmJmIjoiMTU0ODg5NzAzOSJ9.OtJDYOLEF_AtBD6qikE-zg-qnzrJnq1OQ2A9dgiLcWxWNZJjEQdUgei-ZfAB3QJ7zPFLxf-m33TS34WJ6cpbCg"
    }

    ```
    ```json
    {
      "alg": "Ed25519",
      "typ": "JWT"
    }
    {
      "exp": "1548898839",
      "iat": "1548897039",
      "iss": "did:abt:zNKtCNqYWLYWYW3gWRA1vnRykfCBZYHZvzKr",
      "nbf": "1548897039"
    }
    ```
4. The JWT returned in step 9 should be included in header of latter requests as `Authentication` filed.
5. At this point, the authentication process is done.

### Revoke DID Authentication

TBD

## DID

The decentralized identification provided by ArcBlock.

```
    did:abt:z1muQ3xqHQK2uiACHyChikobsiY5kLqtShA
      DID            DID string
    schema
```
### DID Type

DID type is the first two bytes of the DID string's binary format. It contains three sections:
1. The first six bits is the *RoleType* of DID.
    - `account` = 0
    - `node` = 1
    - `device` = 2
    - `application` = 3
    - `smart_contract` = 4
    - `bot` = 5
    - `asset` = 6
    - `stake` = 7
    - `validator` = 8
    - `group` = 9
    - `any` = 63
2. The following 5 bits denotes the *KeyType*, algorithm to convert secret key to public key.
    - `ED25519` = 0
    - `SECP256K1` = 1
3. The latter 5 bits represents the *Hash* function to calculate the hash of public key.
    - `keccak` = 0
    - `sha3` = 1
    - `keccak_384` = 2
    - `sha3_384` = 3
    - `keccak_512 ` = 4
    - `sha3_512 ` = 5

So DID type bytes `0x0C01` can be interpreted as follow:

```
+-------------+-----------+------------+
| 000011      | 00000     | 00001      |
+-------------+-----------+------------+
| application | ed25519   | sha3       |
+-------------+-----------+------------+
```

### Create DID

This process is inspired by Bitcoin. The difference is that we use a single SHA3 to replace SHA256 and RIPEMD160 which are used to do double hash in Bitcoin.

- Step 1: Choose the *RoleType*, *KeyType* and *Hash* from above, let's use `application`, `ed25519` and `sha3` in this example.
- Step 2: Choose a secret key randomly, e.g.
  ```
  D67C071B6F51D2B61180B9B1AA9BE0DD0704619F0E30453AB4A592B036EDE644E4852B7091317E3622068E62A5127D1FB0D4AE2FC50213295E10652D2F0ABFC7
  ```
- Step 3: Generate the public key of this secret key by using the *KeyType*. So we can get public key
  ```
  E4852B7091317E3622068E62A5127D1FB0D4AE2FC50213295E10652D2F0ABFC7
  ```
- Step 4: Get the *Hash* of the public key
  ```
  EC8E681514753FE5955D3E8B57DAEC9D123E3DB146BDDFC3787163F77F057C27
  ```
- Step 5: Take the first 20 bytes of the public key hash
  ```
  EC8E681514753FE5955D3E8B57DAEC9D123E3DB1
  ```
- Step 6: Add the DID type bytes `0x0C01` in front of the hash of Step 4
  ```
  0C01EC8E681514753FE5955D3E8B57DAEC9D123E3DB1
  ```
- Step 7: Get the hash of the extended hash in Step 6
  ```
  42CD815145538F8003586C880AF94418341F9C4B8FA0394876553F8A952C7D03
  ```
- Step 8: Take the first 4 bytes in step 7
  ```
  42CD8151
  ```
- Step 9: Append the 4 bytes in step 8 to the extended hash in step 6. This is the binary DID string
  ```
  0C01EC8E681514753FE5955D3E8B57DAEC9D123E3DB142CD8151
  ```
- Step 10: Encode the binary value by using the Bitcoin Base58 method.
  ```
  zNKtCNqYWLYWYW3gWRA1vnRykfCBZYHZvzKr
  ```
- Step 11: Assemble the parts and get the full DID
  ```
  did:abt:zNKtCNqYWLYWYW3gWRA1vnRykfCBZYHZvzKr
  ```

### Declare DID

Declaring a DID is done by sending a declare transaction to the blockchain. The following is a sample transaction.

```json
{
  "hash": "36BBCA0115A52C0F43C42E84CAE368481A0F32B218380721E3DD2B0456D1D294",
  "tx": {
    "from": "z1RMrcjJVwuohBoqAsPaVvuDajQi1fDo8Qx",
    "itx": {
      "__typename": "DeclareTx",
      "data": null,
      "pk": "IWNMqz5IdsqxO0x9iqdlSfMvPkchVc3un8mmLXT_GcU",
      "type": {
        "address": "BASE58",
        "hash": "SHA3",
        "pk": "ED25519",
        "role": "ROLE_ACCOUNT"
      }
    },
    "nonce": 1,
    "signature": "E_BkPhw-WUpkTk5nn_WF4z-8huOBqjl-3vQ122TYCDQiahFlklVJT3I7YUwr8d-pi_mqMM0JKWB06ayJh3gODQ",
    "signatures": []
  }
}
```

### Read DID

To read a DID, one just need to send a GRPC request to ABT network. The structure of the request is described as follow. The `address` filed is the DID to query. If the `keys` field is omitted, entire account states will be returned. The `height` field can be used to retrieve the older version of the DID documents. If it is omitted, the latest one will be returned.

```
message RequestGetAccountState {
  string address = 1;
  repeated string keys = 2;
  uint64 height = 3;
}
```

The response contains the DID document associated with this DID.

### Update DID

To update associated DID document of a DID, one can send an update transaction like this:

```json
{
  "hash": "36BBCA0115A52C0F43C42E84CAE368481A0F32B218380721E3DD2B0456D1D294",
  "tx": {
    "from": "z1RMrcjJVwuohBoqAsPaVvuDajQi1fDo8Qx",
    "itx": {
      "__typename": "UpdateTx",
      "data": "The new data to replace the existing one.",
      "pk": "IWNMqz5IdsqxO0x9iqdlSfMvPkchVc3un8mmLXT_GcU",
    },
    "nonce": 1,
    "signature": "E_BkPhw-WUpkTk5nn_WF4z-8huOBqjl-3vQ122TYCDQiahFlklVJT3I7YUwr8d-pi_mqMM0JKWB06ayJh3gODQ",
    "signatures": []
  }
}
```

It is worth mentioning that old versions of DID document are still stored on the chain due to the natures of the data structure used by the chain. So this operation is not updating the DID document in place but putting a new version over the existing one.

### Revoke DID

To revoke a DID document, one can send a RevokeTx transaction to mark the DID document as revoked. The DID document will be considered as revoked from the block where the transaction is accepted. This does not mean the DID documents are deleted, they are still stored on the chain.

```
{
  "hash": "36BBCA0115A52C0F43C42E84CAE368481A0F32B218380721E3DD2B0456D1D294",
  "tx": {
    "from": "z1RMrcjJVwuohBoqAsPaVvuDajQi1fDo8Qx",
    "itx": {
      "__typename": "RevokeTx",
      "pk": "IWNMqz5IdsqxO0x9iqdlSfMvPkchVc3un8mmLXT_GcU",
    },
    "nonce": 1,
    "signature": "E_BkPhw-WUpkTk5nn_WF4z-8huOBqjl-3vQ122TYCDQiahFlklVJT3I7YUwr8d-pi_mqMM0JKWB06ayJh3gODQ",
    "signatures": []
  }
}
```

## Verifiable Claims

Verifiable claims is a list of claim item. Each claim item must have a `type` filed and can optionally have a `meta` filed.

There are three types of verifiable claims so far.
- `profile`: A profile can contain multiple well-known predefined claim items, such as `firstName`, `birthday` and so on.
- `agreement`: A peer can ask the users to sign agreements.
- `proofOfHolding`: A peer can require users to prove that they own a certain amount of token or own a certificate issued by a third party.

The `meta` is an optional filed that could contain but is not limited to following fields:
  - `description`: Used to describe the claim. Wallet can display this field to users.

### Profile

Profile is the simplest verifiable claims used to gather users' basic information. A `profile` cliam type should have following fields:

  - `type`: fixed to "profile".
  - `meta`: optional field.
  - `items`: A list of predefined profile items.

When peer requires profile claims, it should add a list of profile items to the response:
  ```json
  {
    "requestedClaims": [
      {
        "type": "profile",
        "meta": {
          "description": "Please provide the basic information.",
        },
        "items": ["fullName", "mobilePhone", "mailingAddress"]
      }
    ]
  }
  ```

After receive this response, the wallet should prompt user to fill in data. Latter, the wallet should return the claims in following format.
  ```json
  {
    "requestedClaims": [
      {
        "type": "profile",
        "meta": {
          "description": "Please provide the basic information",
        },
        "fullName": "Alice Bean",
        "mobilePhone": "123456789",
        "mailingAddress": {
            "addressLine1": "456 123th AVE",
            "addressLine2": "Apt 106",
            "city": "Redmond",
            "state": "WA",
            "postalCode": "98052",
            "country": "USA"
          }
      }
    ]
  }
  ```

#### Predefined claim items:

- `billingAddress`
- `birthday`
- `companyAddress`
- `companyName`
- `driverLicense`
- `firstName`
- `fullName`
- `gender`
- `highestEducationDegree`
- `homeAddress`
- `homePhone`
- `languages`
- `lastName`
- `locale`
- `mailingAddress`
- `maritalStatus`
- `middleName`
- `mobilePhone`
- `nationalId`
- `nationality`
- `passport`
- `personalEmail`
- `photo`
- `placeOfBirth`
- `primaryOccupation`
- `socialSecurityNumber`
- `taxpayerIdNumber`
- `timezone`
- `workEmail`
- `workPhone`

### Agreement

Agreement is another commonly used type of claim. It stands for the agreements that a peer asks the user to sign. An `agreement` claim type should contain following fields:
  - `type`: fixed to "agreement"
  - `meta`: optional field.
  - `uri`: An URI points to the content of the agreement.
  - `hash`: An object where `method` sub field specifies the algorithm (sha3, sha256 and so on) used, and `digest` sub field is the hash result.
  - `agreed`: A boolean value added by wallet to indicate if the user agrees the agreement.
  - `sig`: The DSA signature of the `hash`.

When a peer wants a user to sign agreements, it should add a list of claim item of agreement type in the response. Each claim item has a `meta` containing the URI of the agreement and also a digest of the agreement content.
  ```json
  {
    "requestedClaims": [
      {
        "type": "agreement",
        "meta": {
          "description": "The user data usage agreement.",
        },
        "uri": "https://document-1.io",
        "hash": {
          "method": "sha256",
          "digest": "The hash result of the document's content"
        }
      },
      {
        "type": "agreement",
        "meta": {
          "description": "The service agreement",
        },
        "uri": "ipfs://document-2",
        "hash": {
          "method": "sha3",
          "digest": "The hash result of the document's content"
        }
      }
    ]
  }
  ```

When see this response, the wallet should prompt user to sign the agreements. Latter, the wallet should submit a list of signed claim item back to peer. If the user agrees, then wallet shall add `response` field with `AGREED` and also a `sig` field containing the signature of the user. If the user declines, then wallet just need to add `response` field with `DECLINED`. No signature is required in this situation.
  ```json
  {
    "requestedClaims": [
      {
        "type": "agreement",
        "uri": "https://document-1.io",
        "hash": {
          "method": "sha256",
          "digest": "The hash result of the document's content"
        },
        "agreed": true,
        "sig": "user's signature against the doc digest plus AGREED."
      },
      {
        "type": "agreement",
        "uri": "ipfs://document-2",
        "hash": {
          "method": "sha3",
          "digest": "The hash result of the document's content"
        },
        "agreed": false
      }
    ]
  }
  ```

### Proof of Holding

TBD

## Use Cases

The ABT DID Authentication protocol is a generic peer-to-peer protocol that can be used in any case where authentication is required. It can be used in but is not limited to following scenarios:

- User registration.
- User logon.
- Signing documents.
- Requesting/issuing certificate.
- Applying for VISA.
- Peer-to-peer information exchange.

## Registry Blockchain (TBD)

Registry blockchain is the place where application DID should be registered. It is the decentralized authority providing guidance to wallets whether or not the application it is asking for is trustworthy. A registry blockchain should provide at least following information of an application: `trustLevel`.

#### Trust level

Trust level is a number to relatively show how trustworthy an application is. The registry blockchain is responsible for maintaining the trust level of an application. For example, an application can stake ABT token on ABT chain to increase its trust level. If the application did something evil, it will be punished and its trust level will drop through voting.

## APIs

#### Wallet APIs

- Calculates the userDid for this appDid.
  ```
  cal_userDid(root_user_sk, appDid) returns userDid
  ```

#### Registry blockchain side APIs

- The function called by wallet to get the metadata of `appDid`
  ```
  getAppInfo(appDid) returns {trust_level, app_info}
  ```

#### ForgeSDK
- Helper function to construct the encoded challenge to be signed.
  ```
  construct_challenge(alg, appDid, nbf, exp, iat, callback, claims \\ []) returns  challenge
  ```
- Helper function to verify the signature and DID of a challenge.
  ```
  verify_challenge(challenge, pk)
  verify_did(pk, did)
  ```

## References:

- [iOS Universal Link](https://developer.apple.com/ios/universal-links/)
- [Android App Link](https://developer.android.com/training/app-links/)
- [URL Encoded Form Data](https://www.w3.org/TR/html5/sec-forms.html#urlencoded-form-data)
- [JWT](https://tools.ietf.org/html/rfc7519)
