# Payment server for awallet

The payment server for handling free transfers on AlphaWallet

## Request gas payment for transfer

### POST /claimToken/{address}/{indices}/{v}/{r}/{s}
* @param address address who is to claim the ticket
* @param indices the ticket indices in the smart contract representing tickets
* @param v signature component
* @param r signature component
* @param s signature component
* @return ResponseEntity