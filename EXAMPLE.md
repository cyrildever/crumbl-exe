# Example usage

The following describes a working example of how to use the Crumbl&trade; executable:

1. Create a crumbl with all stakeholders

    ```
    ./crumbl -c --owner-keys ecies:crypto/ecies/keys/owner1.pub --signer-keys ecies:crypto/ecies/keys/trustee1.pub,rsa:crypto/rsa/keys/trustee2.pub cdever@edgewhere.fr
    ```
    You may add the `-out path/to/exampleCrumbl.dat` flag to save the result to a `exampleCrumbl.dat` file.

2. Ask the trustees to decipher their crumbs

    For the first trustee, using ECIES encryption:
    ```
    ./crumbl -x --signer-keys ecies:crypto/ecies/keys/trustee1.pub --signer-secret crypto/ecies/keys/trustee1.sk 580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d0000a8BA5LudBtwkchppK/K9baKtkXybam/B9xmtE5VmfsKGa5qzdNQdL0UQ34eT3khNlUwcM5TkD/encZSYBz+TdIi9b8p7IigJWEHvC5ONkWla1VnxAs6Y0Krjf6q0iZAE0OtXBiaP/p3JPz9cYaWQdXLhUkTHtSbtbW0omZaQ==0100a8BPS6VX1+7XNfytep5H64DpRPi5ODvW+ViMykJey9VlATWi3zA2nbLSK81gUHtDtkJqA9zTLs62VA/jJQqr/rWd3kWCoJFrYd49iQGEkVqv66Z8+IzufmrRywAeEZqRspDVnBXU4hP+U6Mo3kWuQDIaiq2DoB9BQh2YUZfg==020158cs0kKolHuf20OJJ5TLspHXndQ9avYRPfHeWolLgzyu/RhS6domJMVK8aKqyOmayZGoqDUTG/KjIWULG2XsInd34MrUFJyh6l6wJGbzy8czcbapKtEIf+tYc6sILsKDNlji0jhoMK4wZQBkdlDjQb8lMmpi51TEavUM9Qi5fpJb9ur7ChwR7kNNRsNeyt5c+mckSPDEuGMYYLDKxGk3EYLjPr1lSBUDKHpcIBXSc4QvEdhD4cGRXLlauNI+3Ru8RrwlSHUjb6ykxCHhyQOQ3nzuznHS9TmCaUBWHI9YpCU6ZWzHP0H42te1Mb+0faBuVoafe2Oxh3RnsdY9Iwoku5Mg==.1
    ```
    The result should be: `580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d%01AgICAgKWqJ/v0/4=.1`

    For the second trustee, using RSA encryption and an input file:
    ```
    ./crumbl -x -in exampleCrumbl.dat --signer-keys rsa:crypto/rsa/keys/trustee2.pub --signer-secret crypto/rsa/keys/trustee2.sk
    ```
    The result should be: `580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d%02AgICAgKEEqTinyo=.1`

    Here again, you may add the `-out` flag to save these results to files.

3. Finalize the extraction as the owner

    ```
    ./crumbl -x --owner-keys ecies:crypto/ecies/keys/owner1.pub --owner-secret crypto/ecies/keys/owner1.sk -vh 580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d 580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d0000a8BA5LudBtwkchppK/K9baKtkXybam/B9xmtE5VmfsKGa5qzdNQdL0UQ34eT3khNlUwcM5TkD/encZSYBz+TdIi9b8p7IigJWEHvC5ONkWla1VnxAs6Y0Krjf6q0iZAE0OtXBiaP/p3JPz9cYaWQdXLhUkTHtSbtbW0omZaQ==0100a8BPS6VX1+7XNfytep5H64DpRPi5ODvW+ViMykJey9VlATWi3zA2nbLSK81gUHtDtkJqA9zTLs62VA/jJQqr/rWd3kWCoJFrYd49iQGEkVqv66Z8+IzufmrRywAeEZqRspDVnBXU4hP+U6Mo3kWuQDIaiq2DoB9BQh2YUZfg==020158cs0kKolHuf20OJJ5TLspHXndQ9avYRPfHeWolLgzyu/RhS6domJMVK8aKqyOmayZGoqDUTG/KjIWULG2XsInd34MrUFJyh6l6wJGbzy8czcbapKtEIf+tYc6sILsKDNlji0jhoMK4wZQBkdlDjQb8lMmpi51TEavUM9Qi5fpJb9ur7ChwR7kNNRsNeyt5c+mckSPDEuGMYYLDKxGk3EYLjPr1lSBUDKHpcIBXSc4QvEdhD4cGRXLlauNI+3Ru8RrwlSHUjb6ykxCHhyQOQ3nzuznHS9TmCaUBWHI9YpCU6ZWzHP0H42te1Mb+0faBuVoafe2Oxh3RnsdY9Iwoku5Mg==.1 580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d%01AgICAgKWqJ/v0/4=.1 580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d%02AgICAgKEEqTinyo=.1
    ```
    The uncrumbled data (sent to stdout) should be: `cdever@edgewhere.fr`

    Alternatively, you may use an input file for the crumbl:
     ```
    ./crumbl -x -in exampleCrumbl.dat --owner-keys ecies:crypto/ecies/keys/owner1.pub --owner-secret crypto/ecies/keys/owner1.sk -vh 580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d 580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d%01AgICAgKWqJ/v0/4=.1 580fb8a91f05833200dea7d33536aaec9d7ceb256a9858ee68e330e126ba409d%02AgICAgKEEqTinyo=.1
    ```

As of the latest version, the library only processes one crumbl at a time, ie. only the first line in an input file.