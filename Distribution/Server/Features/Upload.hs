{-# LANGUAGE DoRec, RankNTypes, NamedFieldPuns, RecordWildCards #-}
module Distribution.Server.Features.Upload (
    UploadFeature(..),
    UploadResource(..),
    initUploadFeature,
    UploadResult(..),
  ) where

import Distribution.Server.Framework
import Distribution.Server.Framework.BackupDump

import Distribution.Server.Features.Upload.State
import Distribution.Server.Features.Upload.Backup

import Distribution.Server.Features.Core
import Distribution.Server.Features.Users

import Distribution.Server.Users.Backup
import Distribution.Server.Packages.Types
import qualified Distribution.Server.Users.Types as Users
import qualified Distribution.Server.Users.Group as Group
import Distribution.Server.Users.Group (UserGroup(..), GroupDescription(..), nullDescription)
import qualified Distribution.Server.Framework.BlobStorage as BlobStorage
import qualified Distribution.Server.Packages.Unpack as Upload
import Distribution.Server.Packages.PackageIndex (PackageIndex)
import qualified Distribution.Server.Packages.PackageIndex as PackageIndex

import Data.Maybe (fromMaybe)
import Data.Time.Clock (getCurrentTime)
import Data.Function (fix)
import Data.ByteString.Lazy (ByteString)

import Distribution.Package
import Distribution.PackageDescription (GenericPackageDescription)
import Distribution.Text (display)
import qualified Distribution.Server.Util.GZip as GZip

import qualified Data.ByteString.Char8 as C
import Distribution.Server.Features.UserDetails
  (queryUserDetails, accountPublicKey, UserDetailsFeature(..))
import Distribution.Server.Util.OpenPGP (errUnlessValidSignature)

data UploadFeature = UploadFeature {
    -- | The package upload `HackageFeature`.
    uploadFeatureInterface :: HackageFeature,

    -- | Upload resources.
    uploadResource     :: UploadResource,
    -- | The main upload routine. This uses extractPackage on a multipart
    -- request to get contextual information.
    uploadPackage      :: ServerPartE UploadResult,

    --TODO: consider moving the trustee and/or per-package maintainer groups
    --      lower down in the feature hierarchy; many other features want to
    --      use the trustee group purely for auth decisions
    -- | The group of Hackage trustees.
    trusteesGroup      :: UserGroup,
    -- | The group of package uploaders.
    uploadersGroup     :: UserGroup,
    -- | The group of maintainers for a given package.
    maintainersGroup   :: PackageName -> UserGroup,

    -- | Requiring being logged in as the maintainer of a package.
    guardAuthorisedAsMaintainer          :: PackageName -> ServerPartE (),
    -- | Requiring being logged in as the maintainer of a package or a trustee.
    guardAuthorisedAsMaintainerOrTrustee :: PackageName -> ServerPartE (),

    -- | Takes an upload request and, depending on the result of the
    -- passed-in function, either commits the uploaded tarball to the blob
    -- storage or throws it away and yields an error.
    extractPackage     :: (Users.UserId -> UploadResult -> IO (Maybe ErrorResponse))
                       -> ServerPartE (Users.UserId, UploadResult, PkgTarball, Maybe Signature)
}

instance IsHackageFeature UploadFeature where
    getFeatureInterface = uploadFeatureInterface

data UploadResource = UploadResource {
    -- | The page for uploading a package, the same as `corePackagesPage`.
    uploadIndexPage :: Resource,
    -- | The page for deleting a package, the same as `corePackagePage`.
    --
    -- This is fairly dangerous and is not currently used.
    deletePackagePage  :: Resource,
    -- | The maintainers group for each package.
    maintainersGroupResource :: GroupResource,
    -- | The trustee group.
    trusteesGroupResource    :: GroupResource,
    -- | The allowed-uploaders group.
    uploadersGroupResource   :: GroupResource,

    -- | URI for `maintainersGroupResource` given a format and `PackageId`.
    packageMaintainerUri :: String -> PackageId -> String,
    -- | URI for `trusteesGroupResource` given a format.
    trusteeUri  :: String -> String,
    -- | URI for `uploadersGroupResource` given a format.
    uploaderUri :: String -> String
}

-- | The representation of an intermediate result in the upload process,
-- indicating a package which meets the requirements to go into Hackage.
data UploadResult = UploadResult {
    -- The parsed Cabal file.
    uploadDesc :: !GenericPackageDescription,
    -- The text of the Cabal file.
    uploadCabal :: !ByteString,
    -- Any warnings from unpacking the tarball.
    uploadWarnings :: ![String]
}

initUploadFeature :: ServerEnv -> CoreFeature -> UserFeature
                  -> UserDetailsFeature -> IO UploadFeature
initUploadFeature env@ServerEnv{serverStateDir}
                  core@CoreFeature{..} user@UserFeature{..}
                  userDetails@UserDetailsFeature{..} = do

    -- Canonical state
    trusteesState    <- trusteesStateComponent    serverStateDir
    uploadersState   <- uploadersStateComponent   serverStateDir
    maintainersState <- maintainersStateComponent serverStateDir

    -- Recusively tie the knot: the feature contains new user group resources
    -- but we make the functions needed to create those resources along with
    -- the feature
    rec let (feature,
             getTrusteesGroup, getUploadersGroup, makeMaintainersGroup)
              = uploadFeature env core user userDetails
                              trusteesState    trusteesGroup    trusteesGroupResource
                              uploadersState   uploadersGroup   uploadersGroupResource
                              maintainersState maintainersGroup maintainersGroupResource

        (trusteesGroup,  trusteesGroupResource) <-
          groupResourceAt "/packages/trustees"  (getTrusteesGroup  [adminGroup])

        (uploadersGroup, uploadersGroupResource) <-
          groupResourceAt "/packages/uploaders" (getUploadersGroup [adminGroup])

        pkgNames <- PackageIndex.packageNames <$> queryGetPackageIndex
        (maintainersGroup, maintainersGroupResource) <-
          groupResourcesAt "/package/:package/maintainers"
                           (makeMaintainersGroup [adminGroup, trusteesGroup])
                           (\pkgname -> [("package", display pkgname)])
                           (packageInPath coreResource)
                           pkgNames

    return feature

trusteesStateComponent :: FilePath -> IO (StateComponent AcidState HackageTrustees)
trusteesStateComponent stateDir = do
  st <- openLocalStateFrom (stateDir </> "db" </> "HackageTrustees") initialHackageTrustees
  return StateComponent {
      stateDesc    = "Trustees"
    , stateHandle  = st
    , getState     = query st GetHackageTrustees
    , putState     = update st . ReplaceHackageTrustees . trusteeList
    , backupState  = \_ (HackageTrustees trustees) -> [csvToBackup ["trustees.csv"] $ groupToCSV trustees]
    , restoreState = HackageTrustees <$> groupBackup ["trustees.csv"]
    , resetState   = trusteesStateComponent
    }

uploadersStateComponent :: FilePath -> IO (StateComponent AcidState HackageUploaders)
uploadersStateComponent stateDir = do
  st <- openLocalStateFrom (stateDir </> "db" </> "HackageUploaders") initialHackageUploaders
  return StateComponent {
      stateDesc    = "Uploaders"
    , stateHandle  = st
    , getState     = query st GetHackageUploaders
    , putState     = update st . ReplaceHackageUploaders . uploaderList
    , backupState  = \_ (HackageUploaders uploaders) -> [csvToBackup ["uploaders.csv"] $ groupToCSV uploaders]
    , restoreState = HackageUploaders <$> groupBackup ["uploaders.csv"]
    , resetState   = uploadersStateComponent
    }

maintainersStateComponent :: FilePath -> IO (StateComponent AcidState PackageMaintainers)
maintainersStateComponent stateDir = do
  st <- openLocalStateFrom (stateDir </> "db" </> "PackageMaintainers") initialPackageMaintainers
  return StateComponent {
      stateDesc    = "Package maintainers"
    , stateHandle  = st
    , getState     = query st AllPackageMaintainers
    , putState     = update st . ReplacePackageMaintainers
    , backupState  = \_ (PackageMaintainers mains) -> [maintToExport mains]
    , restoreState = maintainerBackup
    , resetState   = maintainersStateComponent
    }

uploadFeature :: ServerEnv
              -> CoreFeature
              -> UserFeature
              -> UserDetailsFeature
              -> StateComponent AcidState HackageTrustees    -> UserGroup -> GroupResource
              -> StateComponent AcidState HackageUploaders   -> UserGroup -> GroupResource
              -> StateComponent AcidState PackageMaintainers -> (PackageName -> UserGroup) -> GroupResource
              -> (UploadFeature,
                  [UserGroup] -> UserGroup,
                  [UserGroup] -> UserGroup,
                  [UserGroup] -> PackageName -> UserGroup)

uploadFeature ServerEnv{serverBlobStore = store}
              CoreFeature{ coreResource
                         , queryGetPackageIndex
                         , updateAddPackage
                         }
              UserFeature{..}
              UserDetailsFeature{..}
              trusteesState    trusteesGroup    trusteesGroupResource
              uploadersState   uploadersGroup   uploadersGroupResource
              maintainersState maintainersGroup maintainersGroupResource
   = ( UploadFeature {..}
     , getTrusteesGroup, getUploadersGroup, makeMaintainersGroup)
   where
    uploadFeatureInterface = (emptyHackageFeature "upload") {
        featureDesc = "Support for package uploads, and define groups for trustees, uploaders, and package maintainers"
      , featureResources =
            [ uploadIndexPage uploadResource
            , groupResource     maintainersGroupResource
            , groupUserResource maintainersGroupResource
            , groupResource     trusteesGroupResource
            , groupUserResource trusteesGroupResource
            , groupResource     uploadersGroupResource
            , groupUserResource uploadersGroupResource
            ]
      , featureState = [
            abstractAcidStateComponent trusteesState
          , abstractAcidStateComponent uploadersState
          , abstractAcidStateComponent maintainersState
          ]
      }

    uploadResource = UploadResource
          { uploadIndexPage      = (extendResource (corePackagesPage coreResource)) { resourcePost = [] }
          , deletePackagePage    = (extendResource (corePackagePage coreResource))  { resourceDelete = [] }
          , maintainersGroupResource = maintainersGroupResource
          , trusteesGroupResource    = trusteesGroupResource
          , uploadersGroupResource   = uploadersGroupResource

          , packageMaintainerUri = \format pkgname -> renderResource
                                     (groupResource maintainersGroupResource) [display pkgname, format]
          , trusteeUri  = \format -> renderResource (groupResource trusteesGroupResource)  [format]
          , uploaderUri = \format -> renderResource (groupResource uploadersGroupResource) [format]
          }

    --------------------------------------------------------------------------------
    -- User groups and authentication
    getTrusteesGroup :: [UserGroup] -> UserGroup
    getTrusteesGroup canModify = fix $ \u -> UserGroup {
        groupDesc = trusteeDescription,
        queryUserList  = queryState  trusteesState   GetTrusteesList,
        addUserList    = updateState trusteesState . AddHackageTrustee,
        removeUserList = updateState trusteesState . RemoveHackageTrustee,
        canAddGroup    = [u] ++ canModify,
        canRemoveGroup = canModify
    }

    getUploadersGroup :: [UserGroup] -> UserGroup
    getUploadersGroup canModify = UserGroup {
        groupDesc      = uploaderDescription,
        queryUserList  = queryState  uploadersState   GetUploadersList,
        addUserList    = updateState uploadersState . AddHackageUploader,
        removeUserList = updateState uploadersState . RemoveHackageUploader,
        canAddGroup    = canModify,
        canRemoveGroup = canModify
    }

    makeMaintainersGroup :: [UserGroup] -> PackageName -> UserGroup
    makeMaintainersGroup canModify name = fix $ \u -> UserGroup {
        groupDesc      = maintainerDescription name,
        queryUserList  = queryState  maintainersState $ GetPackageMaintainers name,
        addUserList    = updateState maintainersState . AddPackageMaintainer name,
        removeUserList = updateState maintainersState . RemovePackageMaintainer name,
        canAddGroup    = [u] ++ canModify,
        canRemoveGroup = [u] ++ canModify
      }

    maintainerDescription :: PackageName -> GroupDescription
    maintainerDescription pkgname = GroupDescription
      { groupTitle = "Maintainers"
      , groupEntity = Just (pname, Just $ "/package/" ++ pname)
      , groupPrologue  = "Maintainers for a package can upload new versions and adjust other attributes in the package database."
      }
      where pname = display pkgname

    trusteeDescription :: GroupDescription
    trusteeDescription = nullDescription { groupTitle = "Package trustees", groupPrologue = "Package trustees are essentially maintainers for the entire package database. They can edit package maintainer groups and upload any package." }

    uploaderDescription :: GroupDescription
    uploaderDescription = nullDescription { groupTitle = "Package uploaders", groupPrologue = "Package uploaders allowed to upload packages. If a package already exists then you also need to be in the maintainer group for that package." }

    guardAuthorisedAsMaintainer :: PackageName -> ServerPartE ()
    guardAuthorisedAsMaintainer pkgname =
      guardAuthorised_ [InGroup (maintainersGroup pkgname)]

    guardAuthorisedAsMaintainerOrTrustee :: PackageName -> ServerPartE ()
    guardAuthorisedAsMaintainerOrTrustee pkgname =
      guardAuthorised_ [InGroup (maintainersGroup pkgname), InGroup trusteesGroup]


    ----------------------------------------------------

    -- This is the upload function. It returns a generic result for multiple formats.
    uploadPackage :: ServerPartE UploadResult
    uploadPackage = do
        guardAuthorised_ [InGroup uploadersGroup]
        pkgIndex <- queryGetPackageIndex
        (uid, uresult, tarball, mbSignature) <- extractPackage $ \uid info ->
                                                  processUpload pkgIndex uid info
        now <- liftIO getCurrentTime
        let (UploadResult pkg pkgStr _) = uresult
            pkgid      = packageId pkg
            cabalfile  = CabalFileText pkgStr
            uploadinfo = (now, uid)
        success <- updateAddPackage pkgid cabalfile uploadinfo
                                    (Just tarball) mbSignature
        if success
          then do
             -- make package maintainers group for new package
            let existedBefore = packageExists pkgIndex pkgid
            when (not existedBefore) $
                liftIO $ addUserList (maintainersGroup (packageName pkgid)) uid
            return uresult
          -- this is already checked in processUpload, and race conditions are highly unlikely but imaginable
          else errForbidden "Upload failed" [MText "Package already exists."]

    -- This is a processing funtion for extractPackage that checks upload-specific requirements.
    -- Does authentication, though not with requirePackageAuth, because it has to be IO.
    -- Some other checks can be added, e.g. if a package with a later version exists
    processUpload :: PackageIndex PkgInfo -> Users.UserId -> UploadResult -> IO (Maybe ErrorResponse)
    processUpload state uid res = do
        let pkg = packageId (uploadDesc res)
        pkgGroup <- queryUserList (maintainersGroup (packageName pkg))
        if packageIdExists state pkg
          then uploadError versionExists --allow trustees to do this?
          else if packageExists state pkg && not (uid `Group.member` pkgGroup)
                 then uploadError (notMaintainer pkg)
                 else return Nothing
      where
        uploadError = return . Just . ErrorResponse 403 [] "Upload failed" . return . MText
        versionExists = "This version of the package has already been uploaded.\n\nAs a matter of "
                     ++ "policy we do not allow package tarballs to be changed after a release "
                     ++ "(so we can guarantee stable md5sums etc). The usual recommendation is "
                     ++ "to upload a new version, and if necessary blacklist the existing one. "
                     ++ "In extraordinary circumstances, contact the administrators."
        notMaintainer pkg = "You are not authorised to upload new versions of this package. The "
                     ++ "package '" ++ display (packageName pkg) ++ "' exists already and you "
                     ++ "are not a member of the maintainer group for this package.\n\n"
                     ++ "If you believe you should be a member of the maintainer group for this "
                     ++ "package, then ask an existing maintainer to add you to the group. If "
                     ++ "this is a package name clash, please pick another name or talk to the "
                     ++ "maintainers of the existing package."

    -- This function generically extracts a package, useful for uploading, checking,
    -- and anything else in the standard user-upload pipeline.
    extractPackage :: (Users.UserId -> UploadResult -> IO (Maybe ErrorResponse))
                   -> ServerPartE (Users.UserId, UploadResult, PkgTarball, Maybe Signature)
    extractPackage processFunc =
        withDataFn (lookInput "package") $ \input ->
            case inputValue input of -- HS6 this has been updated to use the new file upload support in HS6, but has not been tested at all
              (Right _) -> errBadRequest "Upload failed" [MText "package field in form data is not a file."]
              (Left file) ->
                  let fileName    = (fromMaybe "noname" $ inputFilename input)
                  in upload fileName file
      where
        upload name file =
         do -- initial check to ensure logged in.
            --FIXME: this should have been covered earlier
            uid <- guardAuthenticated
            let processPackage :: ByteString -> IO (Either ErrorResponse (UploadResult, BlobStorage.BlobId))
                processPackage content' = do
                    now <- liftIO getCurrentTime
                    -- as much as it would be nice to do requirePackageAuth in here,
                    -- processPackage is run in a handle bracket
                    case Upload.unpackPackage now name content' of
                      Left err -> return . Left $ ErrorResponse 400 [] "Invalid package" [MText err]
                      Right ((pkg, pkgStr), warnings) -> do
                        let uresult = UploadResult pkg pkgStr warnings
                        res <- processFunc uid uresult
                        case res of
                            Nothing ->
                                do let decompressedContent = GZip.decompressNamed file content'
                                   blobIdDecompressed <- BlobStorage.add store decompressedContent
                                   return . Right $ (uresult, blobIdDecompressed)
                            Just err -> return . Left $ err
            mbAccDetails <- queryUserDetails uid
            mbPKey <- return . join $ fmap accountPublicKey mbAccDetails
            -- XXX: The same file is later reopened by
            -- 'BlobStorage.consumeFileWith'.
            tarballBS <- liftIO $ C.readFile file
            (sigFile, sigFileName, _) <- lookFile "signature"
            mbSignature <-
              if null sigFileName  -- no signature was provided
              then return Nothing  -- signatures are optional
              else do
                -- XXX: May fail with the "stack overflow" error.
                sig <- liftIO $ C.readFile sigFile
                now <- liftIO getCurrentTime
                let errUnlessValidSignature' Nothing _ _ _
                      = errBadRequest "Signature verification failed"
                          [MText "Cannot find the public key. Have you uploaded it?"]
                    errUnlessValidSignature' (Just pkey) sign mbCurrTime signedData
                      = errUnlessValidSignature pkey sign mbCurrTime signedData
                errUnlessValidSignature' mbPKey sig (Just now) tarballBS
                return $ Just sig
            mres <- liftIO $ BlobStorage.consumeFileWith store file processPackage
            case mres of
                Left  err -> throwError err
                Right ((res, blobIdDecompressed), blobId) ->
                    return (uid, res, tarball, mbSignature)
                  where
                    tarball = PkgTarball { pkgTarballGz   = blobId,
                                           pkgTarballNoGz = blobIdDecompressed }
