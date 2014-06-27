module OpenPGPTest.Crypto (tests) where

import Test.HUnit
import Distribution.Server.Util.OpenPGP
import qualified Data.ByteString       as BS
import qualified Data.ByteString.Char8 as C
import Data.Set (fromList)
import qualified Crypto.PubKey.RSA as RSA
import Codec.Encryption.OpenPGP.Types

tests :: Test
tests = TestList [ TestLabel "isValidPublicKeyFormat: valid"
                     testIsValidPublicKeyFormatValid
                 , TestLabel "isValidPublicKeyFormat: invalid"
                     testIsValidPublicKeyFormatInvalid
                 , TestLabel "errUnlessValidPublicKeyFormat: Nothing"
                     testErrUnlessValidPublicKeyFormatNothing
                 , TestLabel "errUnlessValidPublicKeyFormat: valid"
                     testErrUnlessValidPublicKeyFormatValid
                 , TestLabel "errUnlessValidPublicKeyFormat: invalid"
                     testErrUnlessValidPublicKeyFormatInvalid
                 , TestLabel "decodePublicKey: valid"
                     testDecodePublicKeyValid
                 , TestLabel "decodePublicKey: invalid"
                     testDecodePublicKeyInvalid
                 , TestLabel "decodeSignature: valid"
                     testDecodeSignatureValid
                 , TestLabel "decodeSignature: invalid"
                     testDecodeSignatureInvalid
                 , TestLabel "verifySignature: valid"
                     testVerifySignatureValid
                 , TestLabel "verifySignature: invalid data"
                     testVerifySignatureInvalidData
                 , TestLabel "verifySignature: invalid key"
                     testVerifySignatureInvalidKey
                 , TestLabel "verifySignature: invalid signature"
                     testVerifySignatureInvalidSignature
                 , TestLabel "errUnlessValidSignature: valid"
                     testErrUnlessValidSignatureValid
                 , TestLabel "errUnlessValidSignature: invalid data"
                     testErrUnlessValidSignatureInvalidData
                 , TestLabel "errUnlessValidSignature: invalid key"
                     testErrUnlessValidSignatureInvalidKey
                 , TestLabel "errUnlessValidSignature: invalid signature"
                     testErrUnlessValidSignatureInvalidSignature
                 ]

publicKey1 :: BS.ByteString
publicKey1 = C.pack "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v1.4.11 (GNU/Linux)\n\nmI0EU6VuvwEEAOA1mG6UuyS3Bu6W5f/kV5ZnfmjM98u8X0TqJDFUfhHDEXoVQ6s+\npmFDfqUH7QDfXHwrYWDP3aOjceV1ceMu/Zgd9ofJ8+/CNLbgnIfe4FIjArN/ZiV0\n//yeR3x0++R4FHcPuS4RSUM32lx45helcojzxdnsWEkeXQRGesuytloZABEBAAG0\nJlRlc3QgS2V5IChkbyBub3QgdXNlKSA8cm9vdEBsb2NhbGhvc3Q+iL4EEwECACgF\nAlOlbr8CGwMFCQPCZwAGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEB5Qwprx\n7lkfqLsD/39RSEE9iJkmsSQZrv8HGUt7FcZliXfmSaZm+LrZNUyr4+HYHSmTGawC\nZ9Wx7a6lH/aMhuyzRO86yw8ohhDtvegp6QWzSVnutrSdq1gUCDnXjueYTBLH1m5H\naTrtft88B75CmrtiyJt0Y1hMhba/VHFpXE/WtUwTKd2r1UAkMhIRuI0EU6VuvwEE\nAJ/mSUPv1/WA4wIU3j+zJ8/ij1Jtc0RufQ8Db1ypX6rJBG38UfG5c+93KqrpkMp3\n2qV1IrsFYVUuA0/AQXgw2LLl9EViHivEv1YGjT1bpX5dTw7HiO5kWZChCd/ejMSq\nP6X0nDQozi8CXCyk6ilFPlpSVC+DK6Tsdc9GbDdRynZpABEBAAGIpQQYAQIADwUC\nU6VuvwIbDAUJA8JnAAAKCRAeUMKa8e5ZH3lwA/4qazbjIwt7OewmIh0rpe3esJT/\nnl2OkWvXKQPonyhWNqubheqpvWRS/SpYbpXUq2ti0DRQ7hou3H2nTUkdTHn+MrZ3\nfr1XYbV3vvs7IBL2GPOROclHd7OIKsk7EFF/cA5eEmBE7RXAAiiu30haMQ8LNxoX\n0AhVzoL6g8gGjU07nA==\n=SqH1\n-----END PGP PUBLIC KEY BLOCK-----\n"

publicKey1TK :: TK
publicKey1TK = TK {_tkKey = (PKPayload {_keyVersion = V4, _timestamp = 1403350719, _v3exp = 0, _pkalgo = RSA, _pubkey = RSAPubKey (RSA.PublicKey {RSA.public_size = 128, RSA.public_n = 157445164909814554234082026596178941546310742553559802842362800744134691419974427949822749154798649116635301679820963729527026671418101627224577734860650710741774422097716471779364472884067972650461604800008276629326550756750305550377868174818336505375471238640530858197014292006381599923402487685456248330777, RSA.public_e = 65537})},Nothing), _tkRevs = [], _tkUIDs = [("Test Key (do not use) <root@localhost>",[SigV4 PositiveCert RSA SHA1 (map (SigSubPacket False) [SigCreationTime 1403350719,KeyFlags (fromList [SignDataKey,CertifyKeysKey]),KeyExpirationTime 63072000,PreferredSymmetricAlgorithms [AES256,AES192,AES128,CAST5,TripleDES],PreferredHashAlgorithms [SHA256,SHA1,SHA384,SHA512,SHA224],PreferredCompressionAlgorithms [ZLIB,BZip2,ZIP],Features (fromList [ModificationDetection]),KeyServerPreferences (fromList [NoModify])]) (map (SigSubPacket False) [Issuer $ read "1E50C29AF1EE591F"]) 43195 [MPI {unMPI = 89405395103981539252410877794191961468717730935081273074733065758104807806134045187159259082618035569160295585158299387976249004358294712505792674066436200009324333689111447850933217460442020544600124036732586294178813945278715150869337028277171160032633416372445782662037195349214791581970869990808779624977}]])], _tkUAts = [], _tkSubs = [(PublicSubkeyPkt (PKPayload {_keyVersion = V4, _timestamp = 1403350719, _v3exp = 0, _pkalgo = RSA, _pubkey = RSAPubKey (RSA.PublicKey {RSA.public_size = 128, RSA.public_n = 112285286360836849340628318047799186390326880495241054277334241821176097166823475807870562039398945434268818803188293188528310915396822470435826513661590023406092071207591983077144465940273661289464388839146091891369850442926005823487966972697595303930892653988259193863059125459920606325807358560875364120169, RSA.public_e = 65537})}),[SigV4 SubkeyBindingSig RSA SHA1 (map (SigSubPacket False) [SigCreationTime 1403350719,KeyFlags (fromList [EncryptStorageKey,EncryptCommunicationsKey]),KeyExpirationTime 63072000]) (map (SigSubPacket False) [Issuer $ read "1E50C29AF1EE591F"]) 31088 [MPI {unMPI = 29787498753160747192878810302542353842157477102984170547605569994201959783235640838569933167253312477893639819428657310131503282354022855796199217296874626016456225347232836777366466299911370371655596160770714261199352258385014326481887040353694111426249567496280813222397850166135308366341305818055707540380}]])]}
publicKey2 :: C.ByteString
publicKey2 = C.pack "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v1.4.11 (GNU/Linux)\n\nmI0EU6YXvQEEALPjLHrGPKK0suwTzDhENcwjrNVX7UjQsUq5dJsAebYW/+8+ddxt\nENEHAyp5ugaTn5YDf75drl2iaOLxm1C/7G+a/tLXtzOy86DgvOxLqMpZMi3JyIQS\nk2DmhUbcy1b4NDVeKcSXRwHCzBhB0lC8cZ0wIjMWPF6YT+KI3ltnjsMNABEBAAG0\nJ1Rlc3QgS2V5MiAoZG8gbm90IHVzZSkgPHJvb3RAbG9jYWxob3N0Poi+BBMBAgAo\nBQJTphe9AhsDBQkDwmcABgsJCAcDAgYVCAIJCgsEFgIDAQIeAQIXgAAKCRDvrF4N\n5LIL/oEuA/wMQ1EAjeEwXrx2gyuraa/J81a+oUbgRD94NB+Ff+h0/XlTGxbfILk6\n3N1qLCsti3sQmdhIRkKyIFPiTMnhXswGxQO/HFhiMBzElga02Qp5QtDuz2Sv2sv7\ns2KJyK4thVnUvhYXcXmRw2xH6dLDpt6YZB1RGHmYn7jQjb1GvAJ3LLiNBFOmF70B\nBADGwkSzwLUEiTEvWhU6LKAfaPI2P+BSC2HLK0QfAxxMmfsSSg8x0bPfkSg0CsZ4\nrRzaoNymXpLFwuyAQ0/ejVnyDLTwPvJY7gns+wCLQto3zBxyKWxdI6zAJZRhTI9o\n/f5DCykdLC6J8NFbwm1qX1HgaGrCaORrzQn1oDjnDB93NwARAQABiKUEGAECAA8F\nAlOmF70CGwwFCQPCZwAACgkQ76xeDeSyC/4YSgQAi94UFSK9tvP8kURHUOXnqn56\nM6LxxDGpgy6Qo+HoKye82qUeDD6AJ1Pp6zPFVO0uJfkTuaAAqr9S3D+z0XqFI9bE\n8imFJ9jr19nbL5WUB71FeIp8rDaZOWLr7d9/uqZ/TJunLQn1V8BKcQgQnuh5P4Jo\ntZ5udauD1nZkxHgxXzU=\n=ai9U\n-----END PGP PUBLIC KEY BLOCK-----\n"

invalidPublicKey :: C.ByteString
invalidPublicKey = C.pack "not a public key"

signature1 :: C.ByteString
signature1 = C.pack "-----BEGIN PGP SIGNATURE-----\nVersion: GnuPG v1.4.11 (GNU/Linux)\n\niJwEAAECAAYFAlOtU/wACgkQHlDCmvHuWR9PfQQAnaOo10ixgxLvI6QOKBs6Noso\n+4cmYV00RGbpm17xeNs09rYwmGCge9ks62SYvsURYBLegPQHqarEQ7eCxY+JbIal\nl+VvkyCYsH0Lsi65jqKgYP2u63g2E+rApjaP3OLJLITLKmqOsHLqt9PSWXUtKBZv\nyQWog6ozCz97Td7fkUY=\n=0R+t\n-----END PGP SIGNATURE-----\n"

signature1Pkt :: Pkt
signature1Pkt = SignaturePkt (SigV4 BinarySig RSA SHA1 [SigSubPacket False $ SigCreationTime 1403868156] [SigSubPacket False . Issuer $ read "1E50C29AF1EE591F"] 20349 [MPI {unMPI = 110698077543428111047224715273958699631847981087218567253661590558115181690504827136607582546178416885880516566662989532420002150575854741439268569931194154411275225286586041763131369103887912450894213420123872627820289586496532348966060862531987719236536074790409408009621281550926689969198259531979046228294}])

signature2 :: C.ByteString
signature2 = C.pack "-----BEGIN PGP SIGNATURE-----\nVersion: GnuPG v1.4.11 (GNU/Linux)\n\niJwEAAECAAYFAlOtVEUACgkQ76xeDeSyC/48ZQQAoZeQffFSziPmEP83n7FWQlBn\ncN68dVLAd2LxY2SYBCDTMocB2V3HGhuUtb7uf4tgdymvcAictaqSGEGMSyT/Iqg7\nKoxe2UU1KxIZWjE6PiT5JTm5A3aZ1Q+VsSII6Zxx3Q0feJY6gXLw7Y+erZ0HViHe\nwpDnqKrouGnt7zUQ0GQ=\n=dbBU\n-----END PGP SIGNATURE-----\n"

invalidSignature :: C.ByteString
invalidSignature = C.pack "not a signature"

testIsValidPublicKeyFormatValid :: Test
testIsValidPublicKeyFormatValid =
  True ~=? (isValidPublicKeyFormat publicKey1)

testIsValidPublicKeyFormatInvalid :: Test
testIsValidPublicKeyFormatInvalid =
  False ~=? (isValidPublicKeyFormat invalidPublicKey)

testErrUnlessValidPublicKeyFormatNothing :: Test
testErrUnlessValidPublicKeyFormatNothing =
  (Right ()) ~=? (errUnlessValidPublicKeyFormat' Nothing)

testErrUnlessValidPublicKeyFormatValid :: Test
testErrUnlessValidPublicKeyFormatValid =
  (Right ()) ~=? (errUnlessValidPublicKeyFormat' $ Just publicKey1)

testErrUnlessValidPublicKeyFormatInvalid :: Test
testErrUnlessValidPublicKeyFormatInvalid =
  (Left invalidPublicKeyFormat) ~=?
  (errUnlessValidPublicKeyFormat' $ Just invalidPublicKey)

testDecodePublicKeyValid :: Test
testDecodePublicKeyValid =
  (Right [publicKey1TK]) ~=? (decodePublicKey' publicKey1)

testDecodePublicKeyInvalid :: Test
testDecodePublicKeyInvalid =
  (Left invalidPublicKeyFormat) ~=? (decodePublicKey' invalidPublicKey)

testDecodeSignatureValid :: Test
testDecodeSignatureValid =
  (Right signature1Pkt) ~=? (decodeSignature' signature1)

testDecodeSignatureInvalid :: Test
testDecodeSignatureInvalid =
  (Left $ Message { header = "Invalid signature format"
                  , body   = "Expected a detached ASCII-armored signature."
                  }
  ) ~=? (decodeSignature' invalidSignature)

testVerifySignatureValid :: Test
testVerifySignatureValid =
  (Right $ read "B10D 6514 06C6 9846 F0BF  C2E6 1E50 C29A F1EE 591F") ~=?
  (verifySignature' publicKey1 signature1 Nothing $ C.pack "secret")

verificationFailed :: Message
verificationFailed = Message { header = "Signature verification failed"
                             , body   = "Does the signature correspond"
                                     ++ " to your key and the tarball?"
                             }

testVerifySignatureInvalidData :: Test
testVerifySignatureInvalidData =
  (Left verificationFailed)  ~=?
  (verifySignature' publicKey1 signature1 Nothing $ C.pack "different secret")

testVerifySignatureInvalidKey :: Test
testVerifySignatureInvalidKey =
  (Left verificationFailed) ~=?
  (verifySignature' publicKey2 signature1 Nothing $ C.pack "secret")

testVerifySignatureInvalidSignature :: Test
testVerifySignatureInvalidSignature =
  (Left verificationFailed) ~=?
  (verifySignature' publicKey1 signature2 Nothing $ C.pack "secret")

testErrUnlessValidSignatureValid :: Test
testErrUnlessValidSignatureValid =
  (Right ()) ~=?
  (errUnlessValidSignature' publicKey1 signature1 Nothing $ C.pack "secret")

testErrUnlessValidSignatureInvalidData :: Test
testErrUnlessValidSignatureInvalidData =
  (Left verificationFailed) ~=?
  (errUnlessValidSignature' publicKey1 signature1 Nothing $
   C.pack "different secret")

testErrUnlessValidSignatureInvalidKey :: Test
testErrUnlessValidSignatureInvalidKey =
  (Left verificationFailed) ~=?
  (errUnlessValidSignature' publicKey2 signature1 Nothing $ C.pack "secret")

testErrUnlessValidSignatureInvalidSignature :: Test
testErrUnlessValidSignatureInvalidSignature =
  (Left verificationFailed) ~=?
  (errUnlessValidSignature' publicKey1 signature2 Nothing $ C.pack "secret")
