module Distribution.Server.Util.OpenPGP
  ( isValidPublicKeyFormat
  , errUnlessValidPublicKeyFormat
  , errUnlessValidPublicKeyFormat'
  , decodePublicKey
  , decodePublicKey'
  , parsePublicKeyBody
  , parsePublicKeyBody'
  , decodePublicKeyBody
  , decodePublicKeyBody'
  , decodeSignature
  , decodeSignature'
  , verifySignature
  , verifySignature'
  , errUnlessValidSignature
  , errUnlessValidSignature'
  , invalidPublicKeyFormat
  , Message(..)
  ) where

import qualified Codec.Encryption.OpenPGP.ASCIIArmor as OpenPGPASCII
import Codec.Encryption.OpenPGP.ASCIIArmor.Types
  (Armor(Armor), ArmorType(ArmorPublicKeyBlock,ArmorSignature))
import Codec.Encryption.OpenPGP.Types
  ( TK(..), Pkt(SignaturePkt), Verification(_verificationSigner)
  , TwentyOctetFingerprint )
import Codec.Encryption.OpenPGP.Signatures (verifyAgainstKeyring)
import Codec.Encryption.OpenPGP.Fingerprint (fingerprint)
import Control.Monad (unless, void)
import qualified Data.ByteString            as BS
import qualified Data.ByteString.Lazy       as BL
import qualified Data.ByteString.Char8      as C
import qualified Data.Conduit      as DC
import qualified Data.Conduit.List as CL
import Data.Conduit.OpenPGP.Keyring (conduitToTKs)
import Data.IxSet (fromList)
import Data.Serialize
  (get, decode, runGetPartial, Result(Fail,Done))
import Data.Time (UTCTime)
import Control.Monad.Identity (runIdentity)

import Distribution.Server.Framework.Error
  (errBadRequest, MessageSpan(MText), ServerPartE)

isValidPublicKeyFormat :: BS.ByteString -> Bool
isValidPublicKeyFormat bs =
  case OpenPGPASCII.decode bs :: Either String [Armor] of
    Right [(Armor ArmorPublicKeyBlock _ _)]
      -> True
    _ -> False

data Message = Message { header :: String
                       , body   :: String
                       } deriving (Show, Eq)

invalidPublicKeyFormat :: Message
invalidPublicKeyFormat =
  Message { header = "Invalid public key format"
          , body   = "The public key must be in the ASCII-armored format."
          }

fromEither :: Either Message a -> ServerPartE a
fromEither expr = case expr of
  Left msg -> errBadRequest (header msg) [MText (body msg)]
  Right v  -> return v


errUnlessValidPublicKeyFormat :: Maybe BS.ByteString -> ServerPartE ()
errUnlessValidPublicKeyFormat mbPKey =
  fromEither $ errUnlessValidPublicKeyFormat' mbPKey

errUnlessValidPublicKeyFormat' :: Maybe BS.ByteString -> Either Message ()
errUnlessValidPublicKeyFormat' mbPKey =
  maybe (Right ())
        (\pkey -> unless (isValidPublicKeyFormat pkey)
                         (Left invalidPublicKeyFormat))
        mbPKey

decodePublicKey :: C.ByteString -> ServerPartE [TK]
decodePublicKey bs = fromEither $ decodePublicKey' bs

decodePublicKey' :: C.ByteString -> Either Message [TK]
decodePublicKey' bs =
  case OpenPGPASCII.decode bs :: Either String [Armor] of
    Right [(Armor ArmorPublicKeyBlock _ bs')]
      -> decodePublicKeyBody' $ BL.toStrict bs'
    _ -> Left invalidPublicKeyFormat

parsePublicKeyBody :: BS.ByteString -> ServerPartE [Pkt]
parsePublicKeyBody bs = fromEither $ parsePublicKeyBody' bs

parsePublicKeyBody' :: BS.ByteString -> Either Message [Pkt]
parsePublicKeyBody' bs =
  go $ runGetPartial get bs
  where
    go (Fail e _)      = Left $ Message { header = "Cannot parse the public key"
                                        , body   = e
                                        }
    go (Done pkt rest) = if BS.null rest
                         then return [pkt]
                         else do
                           pkts <- parsePublicKeyBody' rest
                           return $ pkt : pkts

decodePublicKeyBody :: BS.ByteString -> ServerPartE [TK]
decodePublicKeyBody bs = fromEither $ decodePublicKeyBody' bs

decodePublicKeyBody' :: BS.ByteString -> Either Message [TK]
decodePublicKeyBody' bs = do
  pkts <- parsePublicKeyBody' bs
  return $ runIdentity $ CL.sourceList pkts DC.$= conduitToTKs DC.$$ CL.consume

decodeSignature :: C.ByteString -> ServerPartE Pkt
decodeSignature sig =
  fromEither $ decodeSignature' sig

decodeSignature' :: C.ByteString -> Either Message Pkt
decodeSignature' sig =
  case OpenPGPASCII.decode sig :: Either String [Armor] of
    Right [(Armor ArmorSignature _ bs')]
      -> case (decode $ BL.toStrict bs') :: Either String Pkt of
           Right sigPkt@(SignaturePkt _) -> return sigPkt
           _ -> Left $ Message { header = "Invalid packet type"
                               , body   = "Expected a signature packet."
                               }
    _ -> Left $ Message { header = "Invalid signature format"
                        , body   = "Expected a detached ASCII-armored signature."
                        }

verifySignature :: C.ByteString -> C.ByteString -> Maybe UTCTime -> C.ByteString
                -> ServerPartE TwentyOctetFingerprint
verifySignature pkey sig mbCurrTime signedData = do
  fromEither $ verifySignature' pkey sig mbCurrTime signedData

verifySignature' :: C.ByteString -> C.ByteString -> Maybe UTCTime -> C.ByteString
                 -> Either Message TwentyOctetFingerprint
verifySignature' pkey sig mbCurrTime signedData = do
  tks    <- decodePublicKey' pkey
  sigPkt <- decodeSignature' sig
  case verifyAgainstKeyring (fromList tks) sigPkt mbCurrTime signedData
    of Right v -> return . fingerprint $ _verificationSigner v
       _       -> Left $ Message { header = "Signature verification failed"
                                 , body   = "Does the signature correspond"
                                         ++ " to your key and the tarball?"
                                 }

errUnlessValidSignature :: C.ByteString -> C.ByteString -> Maybe UTCTime
                        -> C.ByteString -> ServerPartE ()
errUnlessValidSignature pkey sig mbCurrTime signedData =
  fromEither $ errUnlessValidSignature' pkey sig mbCurrTime signedData

errUnlessValidSignature' :: C.ByteString -> C.ByteString -> Maybe UTCTime
                         -> C.ByteString -> Either Message ()
errUnlessValidSignature' pkey sig mbCurrTime signedData =
  void $ verifySignature' pkey sig mbCurrTime signedData
