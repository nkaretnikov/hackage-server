module OpenPGPTest.UserDetails (tests) where

import Test.HUnit
import qualified Data.IntMap as IntMap
import qualified Data.Text as T
import qualified Data.ByteString.Char8 as BS
import Text.CSV (CSV)
import qualified Distribution.Server.Features.UserDetails as UD
import Distribution.Server.Features.UserDetails hiding (importUserDetails)
import Distribution.Server.Framework.BackupRestore (Restore(RestoreDone))
import Distribution.Server.Framework.BackupDump (BackupType(FullBackup))

tests :: Test
tests = TestList [ TestLabel "importUserDetails" importUserDetails
                 , TestLabel "exportUserDetails" exportUserDetails
                 ]

userDetailsCSV :: CSV
userDetailsCSV = [ [ "1", "test_no_pkey", "root@localhost", "real"
                   , "Account created by self-registration at 2014-06-08 21:22:07.494589 UTC"
                   , ""
                   ]
                 , [ "2", "test_pkey", "root@localhost", "real"
                   , "Account created by self-registration at 2014-06-08 21:24:04.850396 UTC"
                   , "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v1.4.11 (GNU/Linux)\n\nmI0EU45s7QEEALw2PaE1i4RVaBEjHRjg/YkJkGfBhgQdm5CIUG+ar+n6MTAi8cao\n7tgt0FordZrhSu2WbhHm4A0symlWyigTZR8l8s3UE9nxb70bxNlIvEUx6rnjBRRk\nFK/SGMNQXBc1Zmo0DzmfgJX3EXVK6RNedU05u7mASmkx1ByGwVhSQf0pABEBAAG0\nJlRlc3QgS2V5IChkbyBub3QgdXNlKSA8cm9vdEBsb2NhbGhvc3Q+iL4EEwECACgF\nAlOObO0CGwMFCQABUYAGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEFyfBV89\n+3ZWZmID/iAl7LXlLTssNB/t6Xbxv9DNmG7simb/hUKHiqN1BWnJkjO3SHC72JWC\n5zBZNG/gh+FFbYzukHA1SDlMVhU6E0Zzk127qbZCfEFq+uEpgM2RCC3+O7WrJQMN\n3YW4H+TIxkVhCNcZY7LYEkS0DWIp0cuRQqVgXrm+gVxvgEa8Mme5uI0EU45s7QEE\nAK58d/not6Hu54Qof4FVk8wu7tNNeV03Z5wZWOUlcy59Wo5zh+roZJJDuVNqCWyy\ncU2scTx5oKq5UCqDRsTfSFLA7zSatxwdFPxzJpW8KrzZtaziZsgwLpjeCOPUjIea\nMNd1IUZ/YupCls+Ylu+NwAPKPdP92eesOnyO+ohXhfRxABEBAAGIpQQYAQIADwUC\nU45s7QIbDAUJAAFRgAAKCRBcnwVfPft2VhlSA/94KGm1HiWuXOsSSGTYJPh0QoM2\nDTQec+05/V2Y7yo+2dpIFJTSrUUzQeuQI014So6MlzN2ycfpQFujpUiP1Qwn1ORF\niOZ1GJ7uo/harILGbSdbxwNyN4EKz2xQ6eCOwbvhl3ij2JwGyvWBJ1VCnFOPxobd\nD+j4lDqTyX+iR9laeA==\n=WR1M\n-----END PGP PUBLIC KEY BLOCK-----\n"
                   ]
                 , [ "3", "test_no_pkey2", "root@localhost", "real"
                   , "Account created by self-registration at 2014-06-08 22:36:44.981287 UTC"
                   ,""
                   ]
                 ]

userDetailsTable :: UserDetailsTable
userDetailsTable = UserDetailsTable $ IntMap.unions
  [ IntMap.singleton 1 $
      AccountDetails { accountName         = T.pack "test_no_pkey"
                     , accountContactEmail = T.pack "root@localhost"
                     , accountKind         = Just AccountKindRealUser
                     , accountAdminNotes   = T.pack "Account created by self-registration at 2014-06-08 21:22:07.494589 UTC"
                     , accountPublicKey    = Nothing
                     }
  , IntMap.singleton 2 $
      AccountDetails { accountName         = T.pack "test_pkey"
                     , accountContactEmail = T.pack "root@localhost"
                     , accountKind         = Just AccountKindRealUser
                     , accountAdminNotes   = T.pack "Account created by self-registration at 2014-06-08 21:24:04.850396 UTC"
                     , accountPublicKey    = Just $ BS.pack "-----BEGIN PGP PUBLIC KEY BLOCK-----\nVersion: GnuPG v1.4.11 (GNU/Linux)\n\nmI0EU45s7QEEALw2PaE1i4RVaBEjHRjg/YkJkGfBhgQdm5CIUG+ar+n6MTAi8cao\n7tgt0FordZrhSu2WbhHm4A0symlWyigTZR8l8s3UE9nxb70bxNlIvEUx6rnjBRRk\nFK/SGMNQXBc1Zmo0DzmfgJX3EXVK6RNedU05u7mASmkx1ByGwVhSQf0pABEBAAG0\nJlRlc3QgS2V5IChkbyBub3QgdXNlKSA8cm9vdEBsb2NhbGhvc3Q+iL4EEwECACgF\nAlOObO0CGwMFCQABUYAGCwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEFyfBV89\n+3ZWZmID/iAl7LXlLTssNB/t6Xbxv9DNmG7simb/hUKHiqN1BWnJkjO3SHC72JWC\n5zBZNG/gh+FFbYzukHA1SDlMVhU6E0Zzk127qbZCfEFq+uEpgM2RCC3+O7WrJQMN\n3YW4H+TIxkVhCNcZY7LYEkS0DWIp0cuRQqVgXrm+gVxvgEa8Mme5uI0EU45s7QEE\nAK58d/not6Hu54Qof4FVk8wu7tNNeV03Z5wZWOUlcy59Wo5zh+roZJJDuVNqCWyy\ncU2scTx5oKq5UCqDRsTfSFLA7zSatxwdFPxzJpW8KrzZtaziZsgwLpjeCOPUjIea\nMNd1IUZ/YupCls+Ylu+NwAPKPdP92eesOnyO+ohXhfRxABEBAAGIpQQYAQIADwUC\nU45s7QIbDAUJAAFRgAAKCRBcnwVfPft2VhlSA/94KGm1HiWuXOsSSGTYJPh0QoM2\nDTQec+05/V2Y7yo+2dpIFJTSrUUzQeuQI014So6MlzN2ycfpQFujpUiP1Qwn1ORF\niOZ1GJ7uo/harILGbSdbxwNyN4EKz2xQ6eCOwbvhl3ij2JwGyvWBJ1VCnFOPxobd\nD+j4lDqTyX+iR9laeA==\n=WR1M\n-----END PGP PUBLIC KEY BLOCK-----\n"
                     }
    , IntMap.singleton 3 $
        AccountDetails { accountName         = T.pack "test_no_pkey2"
                       , accountContactEmail = T.pack "root@localhost"
                       , accountKind         = Just AccountKindRealUser
                       , accountAdminNotes   = T.pack "Account created by self-registration at 2014-06-08 22:36:44.981287 UTC"
                       , accountPublicKey    = Nothing
                       }
    ]

importUserDetails :: Test
importUserDetails =
  case UD.importUserDetails userDetailsCSV' (UserDetailsTable IntMap.empty) of
    RestoreDone v -> v ~?= userDetailsTable
    _             -> error "wrong 'Restore' value constructor"
  where
    -- 'UD.importUserDetails' drops the first two list elements.
    userDetailsCSV' = [] : [] : userDetailsCSV

exportUserDetails :: Test
exportUserDetails = (drop 2 $  -- drop the version and the header
  userDetailsToCSV FullBackup userDetailsTable) ~?= userDetailsCSV
