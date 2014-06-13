module Main (main) where

import Test.HUnit (runTestTT, Test(..))
import qualified OpenPGPTest.UserDetails as UserDetails

main = runTestTT $ TestList [UserDetails.tests]
