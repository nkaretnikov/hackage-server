module Distribution.Server.Util.OpenPGP
  ( isValidPublicKeyFormat
  , errInvalidPublicKeyFormat
  , errUnlessValidPublicKeyFormat
  ) where

import qualified Data.ByteString.Char8 as BS
import qualified Codec.Encryption.OpenPGP.ASCIIArmor as OpenPGPASCII
import Codec.Encryption.OpenPGP.ASCIIArmor.Types
  (Armor(Armor), ArmorType(ArmorPublicKeyBlock))
import Distribution.Server.Framework.Error
  (errBadRequest, MessageSpan(MText), ServerPartE)
import Control.Monad (unless)

isValidPublicKeyFormat :: BS.ByteString -> Bool
isValidPublicKeyFormat bs =
  case OpenPGPASCII.decode bs :: Either String [Armor] of
    Right [(Armor ArmorPublicKeyBlock _ _)]
      -> True
    _ -> False

errInvalidPublicKeyFormat :: ServerPartE a
errInvalidPublicKeyFormat =
  errBadRequest "Invalid public key format"
    [MText "The public key must be in the ASCII-armored format."]

errUnlessValidPublicKeyFormat :: Maybe BS.ByteString -> ServerPartE ()
errUnlessValidPublicKeyFormat mbPKey =
  maybe (return ())
        (\pkey -> unless (isValidPublicKeyFormat pkey)
                         errInvalidPublicKeyFormat)
        mbPKey
