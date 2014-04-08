makecert -n "CN=klBase" -sk klBaseKey -pe -sr localmachine -sky exchange -ss TRUST -r klBase.cer
makecert -n "CN=klServer" -sk klServerKey -pe -sr localmachine -ss MY -sky exchange -ic klBase.cer -is TRUST klServer.cer
makecert -n "CN=klClient" -sk klClientKey -pe -sr localmachine -ss MY -sky exchange -ic klBase.cer -is TRUST klClient.cer