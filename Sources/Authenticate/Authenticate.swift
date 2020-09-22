import CED25519Ref10
import Foundation

func randomBytes(_ size: Int) -> [UInt8] {
	let fd = fopen("/dev/urandom", "r")
	var buff = [UInt8](repeating: 0, count: size)
	fread(&buff, 1, size, fd)
	fclose(fd)
	return buff
}

public struct ED25519KeyPair: CustomStringConvertible {
	internal let privateKey: [UInt8]
	internal let publicKey: [UInt8]

	public init() {
		var seed = randomBytes(Int(ED25519_SEED_SIZE))
		var privateKey = [UInt8](repeating: 0, count: Int(ED25519_PRIVATE_KEY_SIZE))
		var publicKey = [UInt8](repeating: 0, count: Int(ED25519_PUBLIC_KEY_SIZE))
		compact_ed25519_keygen(&privateKey, &publicKey, &seed)
		self.privateKey = privateKey
		self.publicKey = publicKey
	}
	
	public var description: String {
		let pKeyString = Data(self.privateKey).base64EncodedString()
		let pubKeyString = Data(self.publicKey).base64EncodedString()
		return "privateKey=\(pKeyString)\npublicKey=\(pubKeyString)"
	}
}

public struct Payload<T>: Codable where T:Codable {
	public let sig: String
	public let dat: T
}

public struct Authenticate {
	let keyPair: ED25519KeyPair

	public init(keyPair: ED25519KeyPair) {
		self.keyPair = keyPair
	}
	
	public func sign<T>(data: T) throws -> Payload<T> where T:Codable {
		let encoder = JSONEncoder()
		var pk = keyPair.privateKey
		var signature: [UInt8] = [UInt8](repeating: 0, count: Int(ED25519_SIGNATURE_SIZE))
		let dat = try encoder.encode(data)
		var bytes = Array<UInt8>(dat)
		compact_ed25519_sign(&signature, &pk, &bytes, bytes.count)
		let sig = Data(signature).base64EncodedString()
		return Payload<T>(sig: sig, dat: data)
	}
	
	public func verify<T>(payload: Payload<T>) throws -> Bool where T:Codable {
		let encoder = JSONEncoder()
		guard let signatureData = Data(base64Encoded: payload.sig) else {
			return false
		}
		var signature = Array<UInt8>(signatureData)
		var pubKey = keyPair.publicKey
		let messageData = try encoder.encode(payload.dat)
		var msgBytes = Array<UInt8>(messageData)
		return compact_ed25519_verify(&signature, &pubKey, &msgBytes, msgBytes.count)
	}
}
