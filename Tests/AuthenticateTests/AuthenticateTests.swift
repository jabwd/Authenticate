import XCTest
@testable import Authenticate

struct TestPayload: Codable {
	let email: String
}

final class AuthenticateTests: XCTestCase {
    func testExample() {
		let keypair = ED25519KeyPair()
		let auth = Authenticate(keyPair: keypair)
		let data = TestPayload(email: "jabwd@exurion.com")
		do {
			let authPayload = try auth.sign(data: data)
			XCTAssert(try auth.verify(payload: authPayload), "Unable to verify signature")
		} catch {
			XCTAssert(false, "Unable to sign or verify")
		}
    }

    static var allTests = [
        ("testExample", testExample),
    ]
}
