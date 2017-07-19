# NTLM_Dic_Attack
Python script to attack NTLM Authentication on web [dictionary attack method]


USAGE:
python NTLM_Bruter.py(-h)           [ Displays help menu ]


python NTLM_Bruter.py -u [target address] -p [Path to File that contains passwords] -d [Path to File that contains usernames] -t [Delay between requests (in second - Default 100 mls)]



EXAMPLE:
python NTLM_Bruter.py -u 127.0.0.1 -p /home/user/passDic -d /home/user/userDic -t .3
[ .3 means 300 mls ]
