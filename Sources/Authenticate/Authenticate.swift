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
	public let secretKey: [UInt8]
	public let publicKey: [UInt8]

	public init() {
		var seed = randomBytes(Int(ED25519_SEED_SIZE))
		var privateKey = [UInt8](repeating: 0, count: Int(ED25519_PRIVATE_KEY_SIZE))
		var publicKey = [UInt8](repeating: 0, count: Int(ED25519_PUBLIC_KEY_SIZE))
		compact_ed25519_keygen(&privateKey, &publicKey, &seed)
		self.secretKey = privateKey
		self.publicKey = publicKey
	}
	
	public init?(secretKey: Data) {
		self.init(secretKey: Array<UInt8>(secretKey))
	}
	
	public init?(secretKey: [UInt8]) {
		guard secretKey.count == Int(ED25519_PRIVATE_KEY_SIZE) else {
			return nil
		}
		var pKey = secretKey
		var pubKey = [UInt8](repeating: 0, count: Int(ED25519_PUBLIC_KEY_SIZE))
		compact_ed25519_calc_public_key(&pubKey, &pKey)
		self.secretKey = pKey
		self.publicKey = pubKey
	}
	
	public var description: String {
		let pKeyString = Data(self.secretKey).base64EncodedString()
		let pubKeyString = Data(self.publicKey).base64EncodedString()
		return "privateKey=\(pKeyString)\npublicKey=\(pubKeyString)"
	}
}

public struct Payload<T>: Codable where T:Codable {
	public let sig: Data
	public let dat: T
}

public struct Authenticate {
	let keyPair: ED25519KeyPair

	public init(keyPair: ED25519KeyPair) {
		self.keyPair = keyPair
	}
	
	public func sign<T>(data: T) throws -> Payload<T> where T:Codable {
		let encoder = JSONEncoder()
		var pk = keyPair.secretKey
		var signature: [UInt8] = [UInt8](repeating: 0, count: Int(ED25519_SIGNATURE_SIZE))
		let dat = try encoder.encode(data)
		var bytes = Array<UInt8>(dat)
		compact_ed25519_sign(&signature, &pk, &bytes, bytes.count)
		return Payload<T>(sig: Data(signature), dat: data)
	}
	
	public func verify<T>(payload: Payload<T>) throws -> Bool where T:Codable {
		let encoder = JSONEncoder()
		var signature = Array<UInt8>(payload.sig)
		var pubKey = keyPair.publicKey
		let messageData = try encoder.encode(payload.dat)
		var msgBytes = Array<UInt8>(messageData)
		return compact_ed25519_verify(&signature, &pubKey, &msgBytes, msgBytes.count)
	}
}
