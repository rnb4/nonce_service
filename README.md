# SpruceID Take Home Assessment

This project demonstrates a web service that verifies ownership of a private key using ed25519 digital signatures and utilizes time sensitive nonces to prevent replay attacks.

The project is broken into 3 parts:

- Verifier: a web service with endpoints `GET /nonce` and `POST /verify`
- Holder: a program that requests a nonce from Verifier, signs it then verifies with Verifier
- Common: a lib for structs shared between Holder and Verifier

## Demo

### 1. Start Verifier

```bash
cargo run --bin verifier
```

### 2. Start Holder

```bash
cargo run --bin holder
```

### 3. Verify

The user will be prompted to press enter.Pressing enter a second time will fail as the nonce will have been consumed. Waiting to long to press enter the first time (default is 5 seconds), will also fail as the nonce will time out.

## Analysis

### Authentication / Authorization

Anyone could request nonces and attempt verification plus the only payload that gets verified is the nonce itself. API keys, and actual claims would be necessary for this program to be of any practical use.

### HTTP

Communication is unencrypted, TLS/HTTPS would be needed in the future.

### Logging

The current implementation has a few print statements to show control flow, but upgrading to proper logging would be much better. Considering the implementation is using tokio, tracing might be a good choice.

### Configuration

It would be nice to have environment variables, configuration files, or command line arguments to change variables such as the nonce timeout and server port.

### Testing

Considering the Holder program essentially tests the Verifier and the assessment did not state testing as a focus, tests are limited. More unit test covering unhappy paths as well as end to end testing would be ideal.

### Nonce Storage

Nonces are stored in memory for simplicity. In the future nonces could be stored in a cache or database to allow for restarts and horizontal scaling.

### Other Considerations

- CI/CD
- Documentation / API spec
- Rate limiting
- multiple key algorithms
- key rotation
- persistent logging
