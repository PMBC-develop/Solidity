#1 Voting

The following contract is quite complex, but showcases a lot of Solidity’s features. It implements a voting contract. Of course, the main problems of electronic voting is how to assign voting rights to the correct persons and how to prevent manipulation. We will not solve all problems here, but at least we will show how delegated voting can be done so that vote counting is automatic and completely transparent at the same time.

The idea is to create one contract per ballot, providing a short name for each option. Then the creator of the contract who serves as chairperson will give the right to vote to each address individually.

The persons behind the addresses can then choose to either vote themselves or to delegate their vote to a person they trust.

At the end of the voting time, `winningProposal()` will return the proposal with the largest number of votes.

For the full contract, please refer to [Ballot.sol](https://github.com/fcdn007/solidity/new/master/example/solidity_doc/Ballot.sol) .



#2 Blind Auction

In this section, we will show how easy it is to create a completely blind auction contract on Ethereum. We will start with an open auction where everyone can see the bids that are made and then extend this contract into a blind auction where it is not possible to see the actual bid until the bidding period ends.

##2.1 Simple Open Auction

The general idea of the following simple auction contract is that everyone can send their bids during a bidding period. The bids already include sending money / ether in order to bind the bidders to their bid. If the highest bid is raised, the previously highest bidder gets her money back. After the end of the bidding period, the contract has to be called manually for the beneficiary to receive his money - contracts cannot activate themselves.

Please refer to [SimpleAuction.sol](https://github.com/fcdn007/solidity/new/master/example/solidity_doc/SimpleAuction.sol). 

##2.2 Blind Auction

The previous open auction is extended to a blind auction in the following. The advantage of a blind auction is that there is no time pressure towards the end of the bidding period. Creating a blind auction on a transparent computing platform might sound like a contradiction, but cryptography comes to the rescue.

During the bidding period, a bidder does not actually send her bid, but only a hashed version of it. Since it is currently considered practically impossible to find two (sufficiently long) values whose hash values are equal, the bidder commits to the bid by that. After the end of the bidding period, the bidders have to reveal their bids: They send their values unencrypted and the contract checks that the hash value is the same as the one provided during the bidding period.

Another challenge is how to make the auction binding and blind at the same time: The only way to prevent the bidder from just not sending the money after he won the auction is to make her send it together with the bid. Since value transfers cannot be blinded in Ethereum, anyone can see the value.

The following contract solves this problem by accepting any value that is larger than the highest bid. Since this can of course only be checked during the reveal phase, some bids might be invalid, and this is on purpose (it even provides an explicit flag to place invalid bids with high value transfers): Bidders can confuse competition by placing several high or low invalid bids.

For the full contract, please refer to [BlindAuction.sol](https://github.com/fcdn007/solidity/new/master/example/solidity_doc/BlindAuction.sol). 



#3 Safe Remote Purchase

For the full contract, please refer to [Purchase.sol](https://github.com/fcdn007/solidity/new/master/example/solidity_doc/Purchase.sol). 



#4 Micropayment Channel

In this section we will learn how to build a simple implementation of a payment channel. It use cryptographics signatures to make repeated transfers of Ether between the same parties secure, instantaneous, and without transaction fees. To do it we need to understand how to sign and verify signatures, and setup the payment channel.

##4.1 Creating and verifying signatures

Imagine Alice wants to send a quantity of Ether to Bob, i.e. Alice is the sender and the Bob is the recipient. Alice only needs to send cryptographically signed messages off-chain (e.g. via email) to Bob and it will be very similar to writing checks.

Signatures are used to authorize transactions, and they are a general tool that is available to smart contracts. Alice will build a simple smart contract that lets her transmit Ether, but in a unusual way, instead of calling a function herself to initiate a payment, she will let Bob do that, and therefore pay the transaction fee. The contract will work as follows:

  1. Alice deploys the  `ReceiverPays` contract, attaching enough Ether to cover the payments that will be made.
  2. Alice authorizes a payment by signing a message with their private key.
  3. Alice sends the cryptographically signed message to Bob. The message does not need to be kept secret (you will understand it later), and the mechanism for sending it does not matter.
  4. Bob claims their payment by presenting the signed message to the smart contract, it verifies the authenticity of the message and then releases the funds.

Creating the signature
Alice does not need to interact with Ethereum network to sign the transaction, the proccess is completely offline. In this tutorial, we will sign messages in the browser using `web3.js` and `MetaMask`. In particular, we will use the standard way described in EIP-762, as it provides a number of other security benefits.

```
/// Hashing first makes a few things easier
var hash = web3.sha3("message to sign");
web3.personal.sign(hash, web3.eth.defaultAccount, function () {...});
```

Note that the `web3.personal.sign` prepends the length of the message to the signed data. Since we hash first, the message will always be exactly 32 bytes long, and thus this length prefix is always the same, making everything easier.

What to Sign
For a contract that fulfills payments, the signed message must include:

The recipient’s address
The amount to be transferred
Protection against replay attacks
A replay attack is when a signed message is reused to claim authorization for a second action. To avoid replay attacks we will use the same as in Ethereum transactions themselves, a so-called nonce, which is the number of transactions sent by an account. The smart contract will check if a nonce is used multiple times.

There is another type of replay attacks, it occurs when the owner deploys a `ReceiverPays` smart contract, performs some payments, and then destroy the contract. Later, she decides to deploy the `ReceiverPays` smart contract again, but the new contract does not know the nonces used in the previous deployment, so the attacker can use the old messages again.

Alice can protect against it including the contract’s address in the message, and only messages containing contract’s address itself will be accepted. This functionality can be found in the first two lines of the `claimPayment()` function in the full contract at the end of this chapter.

Packing arguments
Now that we have identified what information to include in the signed message, we are ready to put the message together, hash it, and sign it. For simplicity, we just concatenate the data. The ethereumjs-abi library provides a function called `soliditySHA3` that mimics the behavior of Solidity’s `keccak256` function applied to arguments encoded using `abi.encodePacked`. Putting it all together, here is a JavaScript function that creates the proper signature for the `ReceiverPays` example:

```
// recipient is the address that should be paid.
// amount, in wei, specifies how much ether should be sent.
// nonce can be any unique number to prevent replay attacks
// contractAddress is used to prevent cross-contract replay attacks
function signPayment(recipient, amount, nonce, contractAddress, callback) {
    var hash = "0x" + ethereumjs.ABI.soliditySHA3(
        ["address", "uint256", "uint256", "address"],
        [recipient, amount, nonce, contractAddress]
    ).toString("hex");

    web3.personal.sign(hash, web3.eth.defaultAccount, callback);
}
```

Recovering the Message Signer in Solidity
In general, ECDSA signatures consist of two parameters, `r` and `s`. Signatures in Ethereum include a third parameter called `v`, that can be used to recover which account’s private key was used to sign in the message, the transaction’s sender. Solidity provides a built-in function ecrecover that accepts a message along with the `r`, `s` and `v` parameters and returns the address that was used to sign the message.

Extracting the Signature Parameters
Signatures produced by web3.js are the concatenation of `r`, `s` and `v`, so the first step is splitting those parameters back out. It can be done on the client, but doing it inside the smart contract means only one signature parameter needs to be sent rather than three. Splitting apart a byte array into component parts is a little messy. We will use inline assembly to do the job in the `splitSignature` function (the third function in the full contract at the end of this chapter).

Computing the Message Hash
The smart contract needs to know exactly what parameters were signed, and so it must recreate the message from the parameters and use that for signature verification. The functions `prefixed` and `recoverSigner` do this and their use can be found in the `claimPayment` function.

For the full contract, please refer to [ReceiverPays.sol](https://github.com/fcdn007/solidity/new/master/example/solidity_doc/ReceiverPays.sol). 

##4.2 Writing a Simple Payment Channel

Alice will now build a simple but complete implementation of a payment channel. Payment channels use cryptographic signatures to make repeated transfers of Ether securely, instantaneously, and without transaction fees.

What is a Payment Channel?
Payment channels allow participants to make repeated transfers of Ether without using transactions. This means that the delays and fees associated with transactions can be avoided. We are going to explore a simple unidirectional payment channel between two parties (Alice and Bob). Using it involves three steps:

Alice funds a smart contract with Ether. This “opens” the payment channel.
Alice signs messages that specify how much of that Ether is owed to the recipient. This step is repeated for each payment.
Bob “closes” the payment channel, withdrawing their portion of the Ether and sending the remainder back to the sender.
Not ethat only steps 1 and 3 require Ethereum transactions, step 2 means that the sender transmits a cryptographically signed message to the recipient via off chain ways (e.g. email). This means only two transactions are required to support any number of transfers.

Bob is guaranteed to receive their funds because the smart contract escrows the Ether and honors a valid signed message. The smart contract also enforces a timeout, so Alice is guaranteed to eventually recover their funds even if the recipient refuses to close the channel. It is up to the participants in a payment channel to decide how long to keep it open. For a short-lived transaction, such as paying an internet cafe for each minute of network access, or for a longer relationship, such as paying an employee an hourly wage, a payment could last for months or years.

Opening the Payment Channel
To open the payment channel, Alice deploys the smart contract, attaching the Ether to be escrowed and specifying the intendend recipient and a maximum duration for the channel to exist. It is the function `SimplePaymentChannel` in the contract, that is at the end of this chapter.

Making Payments
Alice makes payments by sending signed messages to Bob. This step is performed entirely outside of the Ethereum network. Messages are cryptographically signed by the sender and then transmitted directly to the recipient.

Each message includes the following information:

    >The smart contract’s address, used to prevent cross-contract replay attacks.
    >The total amount of Ether that is owed the recipient so far.
A payment channel is closed just once, at the of a series of transfers. Because of this, only one of the messages sent will be redeemed. This is why each message specifies a cumulative total amount of Ether owed, rather than the amount of the individual micropayment. The recipient will naturally choose to redeem the most recent message because that is the one with the highest total. The nonce per-message is not needed anymore, because the smart contract will only honor a single message. The address of the smart contract is still used to prevent a message intended for one payment channel from being used for a different channel.

Here is the modified javascript code to cryptographically sign a message from the previous chapter:

```
function constructPaymentMessage(contractAddress, amount) {
    return ethereumjs.ABI.soliditySHA3(
        ["address", "uint256"],
        [contractAddress, amount]
    );
}

function signMessage(message, callback) {
    web3.personal.sign(
        "0x" + message.toString("hex"),
        web3.eth.defaultAccount,
        callback
    );
}

// contractAddress is used to prevent cross-contract replay attacks.
// amount, in wei, specifies how much Ether should be sent.

function signPayment(contractAddress, amount, callback) {
    var message = constructPaymentMessage(contractAddress, amount);
    signMessage(message, callback);
}
```

Closing the Payment Channel
When Bob is ready to receive their funds, it is time to close the payment channel by calling a close function on the smart contract. Closing the channel pays the recipient the Ether they are owed and destroys the contract, sending any remaining Ether back to Alice. To close the channel, Bob needs to provide a message signed by Alice.

The smart contract must verify that the message contains a valid signature from the sender. The process for doing this verification is the same as the process the recipient uses. The Solidity functions `isValidSignature` and `recoverSigner` work just like their JavaScript counterparts in the previous section. The latter is borrowed from the `ReceiverPays` contract in the previous chapter.

The `close` function can only be called by the payment channel recipient, who will naturally pass the most recent payment message because that message carries the highest total owed. If the sender were allowed to call this function, they could provide a message with a lower amount and cheat the recipient out of what they are owed.

The function verifies the signed message matches the given parameters. If everything checks out, the recipient is sent their portion of the Ether, and the sender is sent the rest via a `selfdestruct`. You can see the `close` function in the full contract.

Channel Expiration
Bob can close the payment channel at any time, but if they fail to do so, Alice needs a way to recover their escrowed funds. An expiration time was set at the time of contract deployment. Once that time is reached, Alice can call  `claimTimeout` to recover their funds. You can see the `claimTimeout` function in the full contract.

After this function is called, Bob can no longer receive any Ether, so it is important that Bob closes the channel before the expiration is reached.

For the full contract, please refer to [SimplePaymentChannel.sol](https://github.com/fcdn007/solidity/new/master/example/solidity_doc/SimplePaymentChannel.sol). 

Note: The function `splitSignature` is very simple and does not use all security checks. A real implementation should use a more rigorously tested library, such as openzepplin’s version of this code.

Verifying Payments
Unlike in our previous chapter, messages in a payment channel aren’t redeemed right away. The recipient keeps track of the latest message and redeems it when it’s time to close the payment channel. This means it’s critical that the recipient perform their own verification of each message. Otherwise there is no guarantee that the recipient will be able to get paid in the end.

The recipient should verify each message using the following process:

  1. Verify that the contact address in the message matches the payment channel.
  2. Verify that the new total is the expected amount.
  3. Verify that the new total does not exceed the amount of Ether escrowed.
  4. Verify that the signature is valid and comes from the payment channel sender.

We’ll use the ethereumjs-util library to write this verifications. The final step can be done a number of ways, but if it’s being done in JavaScript. The following code borrows the constructMessage function from the signing JavaScript code above:

```
// this mimics the prefixing behavior of the eth_sign JSON-RPC method.
function prefixed(hash) {
    return ethereumjs.ABI.soliditySHA3(
        ["string", "bytes32"],
        ["\x19Ethereum Signed Message:\n32", hash]
    );
}
```
function recoverSigner(message, signature) {
    var split = ethereumjs.Util.fromRpcSig(signature);
    var publicKey = ethereumjs.Util.ecrecover(message, split.v, split.r, split.s);
    var signer = ethereumjs.Util.pubToAddress(publicKey).toString("hex");
    return signer;
}

function isValidSignature(contractAddress, amount, signature, expectedSigner) {
    var message = prefixed(constructPaymentMessage(contractAddress, amount));
    var signer = recoverSigner(message, signature);
    return signer.toLowerCase() ==
        ethereumjs.Util.stripHexPrefix(expectedSigner).toLowerCase();
}
