makecert -n "CN=klLicenseKeyGenBase" -sk klLicenseKeyGenBaseKey -pe -sr localmachine -sky exchange -ss TRUST -r klLicenseKeyGenBase.cer
makecert -n "CN=klLicenseKeyGen" -sk klLicenseKeyGenKey -pe -sr localmachine -ss MY -sky exchange -ic klLicenseKeyGenBase.cer -is TRUST klLicenseKeyGen.cer

