module Main (main) where

import Test.HUnit (runTestTT, Test(..))
import qualified OpenPGPTest.UserDetails as UserDetails
import qualified OpenPGPTest.Crypto as Crypto

main = runTestTT $ TestList [UserDetails.tests, Crypto.tests]
