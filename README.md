# Authenticate

A simple swift package that can be used to replace JWT authentication in any project.

## Usage

```
struct User: Codable {
	let userID: Int
	let email: String
}
let data = User(userID: 0, email: "john@appleseed.com")

// Generate a new secretkey / publickey pair
let keyPair = KeyPair()
// Save the private key here :)

let keyPair = KeyPair(secretKey: secretKeyData)
let auth = Authenticate(keyPair: keyPair)
let payload = try auth.sign<User>(data: data)

// Verify
let isCorrect = try auth.verify<User>(payload: payload)
```
