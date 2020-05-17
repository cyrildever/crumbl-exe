# crumbl-exe #

![GitHub tag (latest by date)](https://img.shields.io/github/v/tag/edgewhere/crumbl-exe)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/edgewhere/crumbl-exe)
![GitHub last commit](https://img.shields.io/github/last-commit/edgewhere/crumbl-exe)
![GitHub issues](https://img.shields.io/github/issues/edgewhere/crumbl-exe)
![NPM](https://img.shields.io/npm/l/crumbl-js)

crumbl-exe is both an executable and a Go client for generating secure data storage with trusted signing third-parties using the Crumbl&trade; technology patented by [Edgewhere](https://www.edgewhere.fr).

If you're interesting in using the library, please [contact us](mailto:contact@edgewhere.fr).

### Process ###

The whole process could be divided into two major steps:
* create the _crumbl_ from a source data;
* extract the data out of a _crumbl_.

The first step involves at least two stakeholders, but preferably four for optimal security and sustainability:
* at least one "owner" of the data, ie. the stakeholder that needs to securely store it;
* three signing trusted third-parties who shall remain unaware of the data.

1. Creation

    To create the _crumbl_, one would need the data and the public keys of all the stakeholders, as well as the encryption algorithm used by them.
    Currently, two encryption algorithms are allowed by the system: ECIES and RSA.

    Once created, the _crumbl_ could be stored by anyone: any stakeholder or any outsourced data storage system. 
    The technology guarantees that the _crumbl_ can't be deciphered without the presence of the signing stakeholders, the number of needed stakeholders depending on how many originally signed it, but a data owner must at least be present. In fact, only a data owner will be able to fully recover the original data from the _crumbl_.

2. Extraction

    To extract the data from a _crumbl_ is a multi-step process:
    * First, the data owner should ask the signing trusted third-parties to decipher the parts (the "crumbs") they signed;
    * Each signing trusted third-party should use their own keypair (private and public keys) along with the _crumbl_, and then return the result (the "partial uncrumbs") to the data owner;
    * After, collecting all the partial uncrumbs, the data owner should inject them in the system along with the _crumbl_ and his own keypair to get the fully-deciphered data.


All these steps could be done using command-line instructions with the [executable](#executable), or building an integrated app utilizing the [Go library](#go-library).


### Usage ###

#### Executable ####

```console
git clone https://github.com/edgewhere/crumbl-exe.git && cd crumbl-exe && go build
```

```console
Usage of ./crumbl:
  -c    create a crumbled string from source
  -in string
        file to read an existing crumbl from (WARNING: do not add the crumbl string in the command-line arguments too)
  -out string
        file to save result to
  -owner-keys string
        comma-separated list of colon-separated encryption algorithm prefix and filepath to public key of owner(s)
  -owner-secret string
        filepath to the private key of the owner
  -signer-keys string
        comma-separated list of colon-separated encryption algorithm prefix and filepath to public key of trusted signer(s)
  -signer-secret string
        filepath to the private key of the trusted signer
  -vh string
        optional verification hash of the data
  -x    extract crumbl(s)
```

1. Creation

    To create a _crumbl_, you need to pass the `-c` flag, then to fill in the `--owner-keys` and `--signer-keys` flags in the appropriate format concatenating:
    * the code name of the encryption algorithm to use (`ecies` or `rsa`);
    * a separating colon (`:`);
    * the path to the file holding the public key (using the uncompressed public key in ECIES, and a PEM file for RSA).
    eg. `ecies:path/to/myKey.pub`

    Optionally, you may add the file path to the `-out` flag to save the result into.

    The data to crumbl should be placed at the end of the command line.

    For example, here is a call to crumbl the data `myDataToCrumbl`:
    ```console
    user:~$ ./crumbl -c -out myFile.dat --owner-keys ecies:path/to/myKey.pub --signer-keys ecies:path/to/trustee1.pub,rsa:path/to/trustee2.pub myDataToCrumbl
    SUCCESS - crumbl successfully saved to myFile.dat
    ```

    Not filling the `-out` flag results in sending the _crumbl_ to stdout.

2. Extraction

    i. Get the partial uncrumbs from the signing trusted third-parties

    When asked (generally by sending the _crumbl_ over to them), each signing trusted third-party should use the executable to get the partial uncrumbs, ie. the deciphered crumbs the system assigned them to sign upon creation.

    The signer should pass the `-x` flag, then fill the `--signer-keys` flag with the algorithm and public key information as above and the `--signer-secret` with the path to the file holding the corresponding private key.

    Optionally, the signer may add the file path to the `-out` flag to save the result into.

    The _crumbl_ should be placed either at the end of the command line, or in a file to reference in the `-in` flag.

    For example, here is a call to partially uncrumbl a _crumbl_ placed in a file:
    ```console
    user:~$ ./crumbl -x -in theCrumbl.dat --signer-keys rsa:path/to/trustee2.pub --signer-secret path/to/trustee2.sk
    123fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d%01AgICAgKWqJ/v0/4=.1
    ```
    The second line above is an example of partial uncrumb sent to stdout because the `-out` wasn't defined.

    ii. Fully-decipher the _crumbl_ as the owner

    After receiving every partial uncrumbs from the signing trusted third-parties, the data owner can fully uncrumbl the _crumbl_.

    The owner should pass the `-x` flag, then fill the `--owner-keys` flag with the algorithm and public key information as above and the `--owner-secret` with the path to the file holding his corresponding private key.

    Optionally, the owner may add the file path to the `-out` flag to save the result into.
    He should also provide the `-vh` tag with the stringified value of the hash of the original data. As of the latest version, this hash should use the SHA-256 hash algorithm.

    The partial uncrumbs could have been appended using a separating space to the end of the file used in the `-in` flag, or to the string of the _crumbl_ passed at the end of the command line. Alternatively, the _crumbl_ could be passed using the `-in` flag and the partial uncrumbs passed at the end of the command line.

    For example, here is a call to get the _crumbl_ deciphered using the last scenario:
    ```console
    user:~$ ./crumbl -x -in theCrumbl.dat -vh 123fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d --owner-keys ecies:path/to/myKey.pub --owner-secret path/to/myKey.sk 123fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d%01AgICAgKWqJ/v0/4=.1 123fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d%02AgICAgKEEqTinyo=.1
    myDataToCrumbl
    ```

As of the latest version, the technology only processes one crumbl at a time.

NB: Error(s) and/or warning message(s) are all sent to stderr.

#### Go Library ####

```golang
import "github.com/edgewhere/crumbl-exe"
```

Construct a new `CrumblWorker` client by passing to it all the arguments otherwise passed in the executable as flags (see above).
Then, launch its process.

For example, the code below reproduces the command-line instruction above for crumbl creation:
```golang
import (
      "fmt"
      "github.com/edgewhere/crumbl-exe/client"
)

func main() {
      data := "myDataToCrumbl"
      worker := client.CrumblWorker{
            Mode:             client.CREATION,
            Input:            "",
            Output:           "myFile.dat",
            OwnerKeys:        "ecies:path/to/myKey.pub",
            OwnerSecret:      "",
            SignerKeys:       "ecies:path/to/trustee1.pub,rsa:path/to/trustee2.pub",
            SignerSecret:     "",
            VerificationHash: "",
            Data:             []string{},
      }
      crumbled, err := worker.Process(true)
      if err == nil {
            // Do something with it
            fmt.Printf("%s once crumbled: %s\n", data, crumbled)
      }
}
```
_NB: Passing `false` to the `Process()` method would not return any result or error, ie. mimic the behaviour of the executable._

The code below mimics the use for the owner when he needs to decipher the crumbled data using two partial uncrumbs.
```golang
// Data recovered in other processes
crumbled := "580fb8a91f05833200dea7d33536aaec99df7af5098d296c1bf90c28cebf76d70000a8BKOR0GMVcYJzGjzJ6AU2Sq15QrxbTql/gkWpW5mddRjqpnmDym4HdkBl9Pt9bSPYEcXiBqJqUcTm0oZIevcqWlZPjM4GbBdL6qgR/wBAXZ1I1zah4czAJBMKMdbmOyuAo06NsCu0bqX0DkcZt2UuOax9ATVQymOiDwHzSg==0100a8BHYwWaREFtdRInDh5c/mweXM0SitlvO7hDzlAC8F3TvpYewDaBn4/FiFonKbINTwPQeoibIkXMFw+HKkXn5FEJ8pNtWalbgAFoO2Iy++FguMOt0aH00PVyV4LNBrEy9RUx5C1tJ5kxM6wTua/3mXsOMtXcjoVPIldF+zLg==020158ciYehulbTIg2p8EueDXRWl7EmnSsLo+sbOPsogMamWxs0MkzXhqPhpTfgKsBnnQ4g32rnwvQs5JyVfOR33LKz+XIgiwSSszOE96TTSp6EMDlEuijp/PK1qmCha/TAJ+o8odJy6tasON/OwWCRUq6hX+ZwKaw1s+xYWpsK7u1ugAtitjpo66xt0LZTtZpmAqT9jZa+1CXQLUsT/TGHovsq45GZJe9zLnuPgxVKjbHrS9xHKSU1P7aQ7zcaZwh+PAmxu+egFXC5U5YYeFmoCBXbN9dk8/sG+qb/T5Z1wVhcogVic6aYNmigxY/DpoErUCooyEGwJVunu+7vpgFeMnz+w==.1"
partialUncrumb1 := "580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d%01AgIEVQMOTg9cRwk=.1"
partialUncrumb2 := "580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d%02AgICAgICAgIYUkI=.1"

worker := client.CrumblWorker{
      Mode:             client.EXTRACTION,
      OwnerKeys:        "ecies:path/to/myKey.pub",
      OwnerSecret:      "path/to/mySecret.key",
      VerificationHash: "580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d",
      Data:             []string{crumbled, partialUncrumb1, partialUncrumb2},
}
result, err := worker.Process(true)
```

Also, there is a method to only extract the verification hash and the crumbs from a crumbled data.
```golang
import  "github.com/edgewhere/crumbl-exe/core"

verificationHash, crumbs, err := core.ExtractData(crumbled)
```

You may want to wrap each process in separate goroutines.

#### Javascript Library ####

You might want to check out the JS implementation for the Crumbl&trade;: [`crumbl-js`](https://github.com/edgewhere/crumbl-js), a Javascript client developed in TypeScript for generating secure data storage with trusted signing third-parties using the Crumbl&trade; technology patented by Edgewhere.


#### Scala Library ####

You might also want to check out the Scala implementation for the Crumbl&trade;: [`crumbl-jar`](https://github.com/edgewhere/crumbl-jar), a Scala client for the JVM and an executable JAR as well.


### License ###

The use of the Crumbl&trade; executable or library for commercial purpose is subject to fees for commercial purpose and to the respect of the [BSD-2-Clause-Patent License](LICENSE).
All technologies are protected by patents owned by Edgewhere.
Please [contact us](mailto:contact@edgehere.fr) to get further information.


<hr />
&copy; 2019-2020 Edgewhere SAS. All rights reserved.